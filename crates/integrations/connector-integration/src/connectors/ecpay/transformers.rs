use std::collections::HashMap;

use common_enums::AttemptStatus;
use common_utils::errors::CustomResult;
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, RSync, Refund, Void},
    connector_types::{
        PaymentFlowData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::PaymentMethodDataTypes,
    router_data::ConnectorSpecificConfig,
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack::{Report, ResultExt};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::EcpayRouterData;
use crate::types::ResponseRouterData;

#[derive(Debug, Clone)]
pub struct EcpayAuthType {
    pub merchant_id: Secret<String>,
    pub hash_key: Secret<String>,
    pub hash_iv: Secret<String>,
}

impl TryFrom<&ConnectorSpecificConfig> for EcpayAuthType {
    type Error = Report<errors::IntegrationError>;

    fn try_from(auth_type: &ConnectorSpecificConfig) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificConfig::Ecpay {
                api_key,
                hash_key,
                hash_iv,
                ..
            } => Ok(Self {
                merchant_id: api_key.to_owned(),
                hash_key: hash_key.to_owned(),
                hash_iv: hash_iv.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::IntegrationError::FailedToObtainAuthType {
                    context: errors::IntegrationErrorContext::default()
                }
            )),
        }
    }
}

// ============================================================================
// CheckMacValue (CMV) computation
// ============================================================================

pub fn compute_check_mac_value(
    params: &HashMap<String, String>,
    hash_key: &str,
    hash_iv: &str,
) -> CustomResult<String, errors::IntegrationError> {
    let mut sorted_params: Vec<(&String, &String)> = params.iter().collect();
    sorted_params.sort_by_key(|(k, _)| k.to_lowercase());

    let mut query = format!("HashKey={hash_key}");
    for (key, value) in &sorted_params {
        query.push('&');
        query.push_str(&ecpay_url_encode(key));
        query.push('=');
        query.push_str(&ecpay_url_encode(value));
    }
    query.push_str("&HashIV=");
    query.push_str(hash_iv);

    let encoded = ecpay_url_encode_full(&query);
    let lower = encoded.to_lowercase();

    let hash = sha2::Sha256::digest(lower.as_bytes());
    let hex = hex::encode(hash);

    Ok(hex.to_uppercase())
}

fn ecpay_url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace("%2D", "-")
        .replace("%5F", "_")
        .replace("%2E", ".")
        .replace("%21", "!")
        .replace("%2A", "*")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%7E", "~")
}

fn ecpay_url_encode_full(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace("%2D", "-")
        .replace("%5F", "_")
        .replace("%2E", ".")
        .replace("%21", "!")
        .replace("%2A", "*")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%7E", "~")
}

// ============================================================================
// Authorize Request
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayAuthorizeRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub merchant_trade_date: String,
    pub payment_type: String,
    pub total_amount: i64,
    pub trade_desc: String,
    pub item_name: String,
    pub return_url: String,
    pub choose_payment: String,
    pub check_mac_value: String,
    pub encrypt_type: i32,
    pub client_back_url: Option<String>,
    pub order_result_url: Option<String>,
    pub need_extra_paid_info: Option<String>,
    pub platform_id: Option<String>,
    pub custom_field_1: Option<String>,
    pub custom_field_2: Option<String>,
    pub custom_field_3: Option<String>,
    pub custom_field_4: Option<String>,
    pub language: Option<String>,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for EcpayAuthorizeRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item
            .router_data
            .resource_common_data
            .connector_request_reference_id
            .clone();
        let now_utc = chrono::Utc::now();
        let merchant_trade_date = now_utc
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .format("%Y/%m/%d %H:%M:%S")
            .to_string();

        let total_amount = item.router_data.request.minor_amount.get_amount_as_i64();
        let trade_desc = item
            .router_data
            .request
            .customer_name
            .clone()
            .unwrap_or_else(|| "ECPay payment".to_string());

        let item_name = "Product".to_string();

        let return_url = item
            .router_data
            .request
            .webhook_url
            .clone()
            .ok_or_else(|| errors::IntegrationError::MissingRequiredField {
                field_name: "webhook_url",
                context: errors::IntegrationErrorContext::default(),
            })?;

        let choose_payment = "ALL".to_string();

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("MerchantTradeDate".to_string(), merchant_trade_date.clone());
        params.insert("PaymentType".to_string(), "aio".to_string());
        params.insert("TotalAmount".to_string(), total_amount.to_string());
        params.insert("TradeDesc".to_string(), trade_desc.clone());
        params.insert("ItemName".to_string(), item_name.clone());
        params.insert("ReturnURL".to_string(), return_url.clone());
        params.insert("ChoosePayment".to_string(), choose_payment.clone());
        params.insert("EncryptType".to_string(), "1".to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            merchant_trade_date,
            payment_type: "aio".to_string(),
            total_amount,
            trade_desc,
            item_name,
            return_url,
            choose_payment,
            check_mac_value,
            encrypt_type: 1,
            client_back_url: item.router_data.request.complete_authorize_url.clone(),
            order_result_url: None,
            need_extra_paid_info: None,
            platform_id: None,
            custom_field_1: None,
            custom_field_2: None,
            custom_field_3: None,
            custom_field_4: None,
            language: None,
        })
    }
}

// ============================================================================
// Authorize Response (HTML form redirect)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayAuthorizeResponse {
    pub html_content: String,
    pub endpoint: String,
    pub form_fields: HashMap<String, String>,
}

impl<T: PaymentMethodDataTypes>
    TryFrom<
        ResponseRouterData<
            EcpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    > for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayAuthorizeResponse,
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
        >,
    ) -> Result<Self, Self::Error> {
        let redirection_data = Some(Box::new(RedirectForm::Form {
            endpoint: item.response.endpoint,
            method: common_utils::Method::Post,
            form_fields: item.response.form_fields,
        }));

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(
                    item.router_data
                        .resource_common_data
                        .connector_request_reference_id
                        .clone(),
                ),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status: AttemptStatus::AuthenticationPending,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// PSync Request/Response
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayPSyncRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub time_stamp: i64,
    pub check_mac_value: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for EcpayPSyncRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::IntegrationError::MissingConnectorTransactionID {
                context: errors::IntegrationErrorContext::default(),
            })?;

        let time_stamp = chrono::Utc::now().timestamp();

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("TimeStamp".to_string(), time_stamp.to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            time_stamp,
            check_mac_value,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayPSyncResponse {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub trade_amt: i64,
    pub payment_date: String,
    pub payment_type: String,
    pub trade_date: String,
    pub trade_status: String,
    pub item_name: String,
    pub check_mac_value: String,
}

impl
    TryFrom<
        ResponseRouterData<
            EcpayPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    > for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayPSyncResponse,
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.trade_status.as_str() {
            "1" => AttemptStatus::Charged,
            "0" => AttemptStatus::Pending,
            _ => AttemptStatus::Failure,
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.trade_no.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_trade_no.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// Capture Request/Response (DoAction Action=C)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayCaptureRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub action: String,
    pub total_amount: i64,
    pub check_mac_value: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for EcpayCaptureRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item
            .router_data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::IntegrationError::MissingConnectorTransactionID {
                context: errors::IntegrationErrorContext::default(),
            })?;
        let trade_no = merchant_trade_no.clone();

        let total_amount = item
            .router_data
            .request
            .minor_amount_to_capture
            .get_amount_as_i64();

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("TradeNo".to_string(), trade_no.clone());
        params.insert("Action".to_string(), "C".to_string());
        params.insert("TotalAmount".to_string(), total_amount.to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            trade_no,
            action: "C".to_string(),
            total_amount,
            check_mac_value,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayCaptureResponse {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub rtn_code: i64,
    pub rtn_msg: String,
}

impl
    TryFrom<
        ResponseRouterData<
            EcpayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayCaptureResponse,
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = if item.response.rtn_code == 1 {
            AttemptStatus::Charged
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.trade_no.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_trade_no.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// Refund Request/Response (DoAction Action=R)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayRefundRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub action: String,
    pub total_amount: i64,
    pub check_mac_value: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for EcpayRefundRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item.router_data.request.connector_transaction_id.clone();
        let trade_no = merchant_trade_no.clone();
        let total_amount = item
            .router_data
            .request
            .minor_refund_amount
            .get_amount_as_i64();

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("TradeNo".to_string(), trade_no.clone());
        params.insert("Action".to_string(), "R".to_string());
        params.insert("TotalAmount".to_string(), total_amount.to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            trade_no,
            action: "R".to_string(),
            total_amount,
            check_mac_value,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayRefundResponse {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub rtn_code: i64,
    pub rtn_msg: String,
}

impl
    TryFrom<
        ResponseRouterData<
            EcpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    > for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayRefundResponse,
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = if item.response.rtn_code == 1 {
            common_enums::RefundStatus::Success
        } else {
            common_enums::RefundStatus::Failure
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.trade_no.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// RSync Request/Response
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayRSyncRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub time_stamp: i64,
    pub check_mac_value: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for EcpayRSyncRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item.router_data.request.connector_transaction_id.clone();
        let time_stamp = chrono::Utc::now().timestamp();

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("TimeStamp".to_string(), time_stamp.to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            time_stamp,
            check_mac_value,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayRSyncResponse {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub trade_amt: i64,
    pub payment_date: String,
    pub payment_type: String,
    pub trade_date: String,
    pub trade_status: String,
    pub check_mac_value: String,
}

impl
    TryFrom<
        ResponseRouterData<
            EcpayRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    > for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayRSyncResponse,
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.trade_status.as_str() {
            "1" => common_enums::RefundStatus::Success,
            "0" => common_enums::RefundStatus::Pending,
            _ => common_enums::RefundStatus::Failure,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.trade_no.clone(),
                refund_status: status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============================================================================
// Void Request/Response (DoAction Action=N)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct EcpayVoidRequest {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub action: String,
    pub total_amount: i64,
    pub check_mac_value: String,
}

impl<T: PaymentMethodDataTypes + std::fmt::Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        EcpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for EcpayVoidRequest
{
    type Error = Report<errors::IntegrationError>;

    fn try_from(
        item: EcpayRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = EcpayAuthType::try_from(&item.router_data.connector_config).change_context(
            errors::IntegrationError::FailedToObtainAuthType {
                context: errors::IntegrationErrorContext::default(),
            },
        )?;

        let merchant_trade_no = item.router_data.request.connector_transaction_id.clone();
        let trade_no = merchant_trade_no.clone();
        let total_amount = 0i64;

        let mut params = HashMap::new();
        params.insert("MerchantID".to_string(), auth.merchant_id.peek().clone());
        params.insert("MerchantTradeNo".to_string(), merchant_trade_no.clone());
        params.insert("TradeNo".to_string(), trade_no.clone());
        params.insert("Action".to_string(), "N".to_string());
        params.insert("TotalAmount".to_string(), total_amount.to_string());

        let check_mac_value =
            compute_check_mac_value(&params, auth.hash_key.peek(), auth.hash_iv.peek())
                .change_context(errors::IntegrationError::RequestEncodingFailed {
                    context: errors::IntegrationErrorContext::default(),
                })?;

        Ok(Self {
            merchant_id: auth.merchant_id.peek().clone(),
            merchant_trade_no,
            trade_no,
            action: "N".to_string(),
            total_amount,
            check_mac_value,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayVoidResponse {
    pub merchant_id: String,
    pub merchant_trade_no: String,
    pub trade_no: String,
    pub rtn_code: i64,
    pub rtn_msg: String,
}

impl
    TryFrom<
        ResponseRouterData<
            EcpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    > for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            EcpayVoidResponse,
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
        >,
    ) -> Result<Self, Self::Error> {
        let status = if item.response.rtn_code == 1 {
            AttemptStatus::Voided
        } else {
            AttemptStatus::Failure
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.trade_no.clone()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.merchant_trade_no.clone()),
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EcpayErrorResponse {
    pub code: String,
    pub message: String,
}

// ============================================================================
// GetFormData implementations
// ============================================================================

use crate::connectors::macros::GetFormData;
use crate::utils::build_form_from_struct;
use common_utils::request::MultipartData;

impl GetFormData for EcpayAuthorizeRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}

impl GetFormData for EcpayPSyncRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}

impl GetFormData for EcpayCaptureRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}

impl GetFormData for EcpayRefundRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}

impl GetFormData for EcpayRSyncRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}

impl GetFormData for EcpayVoidRequest {
    fn get_form_data(&self) -> MultipartData {
        build_form_from_struct(self).unwrap_or_else(|_| MultipartData::new())
    }
}
