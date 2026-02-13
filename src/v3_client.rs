use async_symm_crypto::AsyncEncryption;
use flutterwave_models::{
    api_responses::ResponseType,
    common::payload::Payload,fwcall::ToFwCall,
    charge::{ach::AchReq, bank_transfer::BankTransferReq, direct_charge::CardChargeReq},
    encrypted_payload::EncryptedPayload,
    errors::FWaveError,
    payment_plans::{CancelPlanReq, CreatePlanReq, GetPlanReq, GetPlansReq, UpdatePlanReq},
    preauthorization::{
        capture_preauth_charge::CapturePreAuthChargeReq,
        refund_preauth_charge::RefundPreAuthChargeReq, void_preauth_charge::VoidPreAuthChargeReq,
    },
    transactions::{
        fetch_refunded_trans::{FetchMultiRefundedTransReq, FetchRefundedTransReq},
        get_transactions::GetTransactionsReq,
        query_trans_fees::QueryTransFeesReq,
        refund_trans::RefundTransactionReq,
        resend_failed_webhook::ResendFailedWebhookReq,
        transaction_verify::{VerifyTransByIdReq, VerifyTransByTxRefReq},
        view_trans_timeline::ViewTransTimelineReq,
    },
    validate_charge::ValidateChargeReq,
    virtual_acct_number::{
        create_virtual_account::{VirtualAcctBulkCreationReq, VirtualAcctCreationReq},
        get_bulk_virtual_acct_details::BulkVirtualAcctDetailsReq,
    },
};
use reqwest::{
    header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE},
    Url,
};
use std::str::FromStr;

macro_rules! generate_client_methods {
    (
        $(
            ($t:ty, $func_name:ident)
        )+
    ) => {
        $(
            #[allow(unused)]
            pub async fn $func_name(
                &self,
                req: $t,
            ) -> Result<ResponseType<<$t as ToFwCall>::ApiResponse>, FWaveError> {
                self.make_v3_request(req).await
            }
        )+
    };
}

static BASE_URL: &str = "https://api.flutterwave.com/";

pub struct FWV3Client<'a> {
    #[allow(unused)]
    enc_key: &'a str,
    #[allow(unused)]
    public: &'a str,
    #[allow(unused)]
    secret: &'a str,
    client: reqwest::Client,
    crypt: AsyncEncryption<'a>,
}

impl<'a> FWV3Client<'a> {
    pub fn new(secret_key: &'a str, public_key: &'a str, encryption_key: &'a str) -> Self {
        let mut default_headers = HeaderMap::new();
        default_headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        default_headers.append(ACCEPT, HeaderValue::from_static("application/json"));

        let client = reqwest::ClientBuilder::new()
            .https_only(true)
            .default_headers(default_headers)
            .build()
            .unwrap();

        Self {
            secret: secret_key,
            public: public_key,
            enc_key: encryption_key,
            client,
            crypt: AsyncEncryption::new(
                openssl::symm::Cipher::des_ede3_ecb(),
                secret_key.as_bytes(),
                None,
            ),
        }
    }

    async fn make_v3_request<'b, C: ToFwCall<'b> + 'b>(
        &'b self,
        call: C,
    ) -> Result<ResponseType<C::ApiResponse>, FWaveError> {
        let call = call.get_call();

        let mut request = self
            .client
            .request(
                call.method.clone(),
                Url::from_str(BASE_URL)
                    .unwrap()
                    .join(call.path.as_ref())
                    .unwrap(),
            )
            .bearer_auth(self.secret)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json");

        if [reqwest::Method::PUT, reqwest::Method::POST].contains(&call.method) {
            match &call.payload {
                Some(Payload::Plain(pload)) => {
                    request = request.json(&pload);
                }
                Some(Payload::ToEncrypt(pload)) => {
                    let to_enc_bytes = serde_json::to_string(pload)?.as_bytes().to_vec();
                    let encrypted_bytes = self.crypt.encrypt(&to_enc_bytes).await.unwrap();
                    request = request.json(&EncryptedPayload::new(openssl::base64::encode_block(
                        &encrypted_bytes,
                    )));
                }
                None => {}
            }
        }

        let response = request.send().await?;
        let status = response.status();
        Ok(response.json::<ResponseType<C::ApiResponse>>().await?.replace_stat_code(status))
    }

    generate_client_methods!(
        // Charge
        (CardChargeReq, initiate_card_charge)
        (BankTransferReq, initiate_bank_transfer)
        (AchReq, initiate_ach_payment)

        // Verify Trans
        (VerifyTransByIdReq, verify_trans_by_id)
        (VerifyTransByTxRefReq, verify_trans_by_txref)

        // Validate Charge
        (ValidateChargeReq, validate_charge)

        // PreAuth
        (CapturePreAuthChargeReq, capture_preauth_charge)
        (VoidPreAuthChargeReq, void_preauth_charge)
        (RefundPreAuthChargeReq, refund_preauth_charge)

        // Virtual Acct
        (BulkVirtualAcctDetailsReq, get_bulk_virtual_acct_details)
        (VirtualAcctCreationReq, create_virtual_acct_no)
        (VirtualAcctBulkCreationReq, create_bulk_virtual_acct_no)

        // Transactions
        (FetchRefundedTransReq, fetch_refunded_transactions)
        (FetchMultiRefundedTransReq, fetch_multi_refunded_transactions)
        (GetTransactionsReq, get_transaction)
        (QueryTransFeesReq, query_transaction_fees)
        (RefundTransactionReq, refund_transaction)
        (ResendFailedWebhookReq, resend_failed_webhook)
        (ViewTransTimelineReq, view_trans_imeline)

        // Payment Plans
        (CreatePlanReq, create_payment_plan)
        (GetPlanReq, get_payment_plan)
        (GetPlansReq, get_payment_plans)
        (CancelPlanReq, cancel_payment_plan)
        (UpdatePlanReq, update_payment_plan)
    );
}
