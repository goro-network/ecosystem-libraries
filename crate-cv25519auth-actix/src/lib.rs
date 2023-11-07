use actix_http::HttpMessage;
use futures::StreamExt;

extern crate alloc;

pub struct Cv25519Authenticator;

impl Cv25519Authenticator {
    pub const EMPTY_PAYLOAD: [u8; 4] = 0x600dd33d_u32.to_be_bytes();
    pub const HEADER_IDENTITY: &str = "nagara-id";
    pub const HEADER_SIGNATURE: &str = "nagara-signature";
}

impl<S, Req> actix_web::dev::Transform<S, actix_web::dev::ServiceRequest> for Cv25519Authenticator
where
    S: actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse<Req>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
    S: 'static,
{
    type Error = actix_web::Error;
    type Future = core::future::Ready<core::result::Result<Self::Transform, Self::InitError>>;
    type InitError = ();
    type Response = actix_web::dev::ServiceResponse<Req>;
    type Transform = Cv25519AuthenticatorService<S>;

    fn new_transform(&self, service: S) -> Self::Future {
        nagara_logging::debug!("Creating new transform");

        core::future::ready(Ok(Cv25519AuthenticatorService {
            wrapped_service: alloc::rc::Rc::new(core::cell::RefCell::new(service)),
        }))
    }
}

pub struct Cv25519AuthenticatorService<S> {
    wrapped_service: alloc::rc::Rc<core::cell::RefCell<S>>,
}

impl<S> Cv25519AuthenticatorService<S> {
    fn compose_error_for_bad_header(header_name: &str) -> actix_web::Error {
        actix_web::error::ErrorUnauthorized(alloc::format!("Bad header {header_name:?}"))
    }

    fn try_get_header_value<'a>(
        headers: &'a actix_http::header::HeaderMap,
        header_name: &'a str,
    ) -> core::result::Result<&'a str, actix_web::Error> {
        headers
            .get(header_name)
            .ok_or(Self::compose_error_for_bad_header(header_name))?
            .to_str()
            .map_err(|_| Self::compose_error_for_bad_header(header_name))
    }

    fn try_get_verified_identity_from_headers(
        headers: actix_http::header::HeaderMap,
        payload_bytes: &[u8],
    ) -> core::result::Result<nagara_identities::CryptographicIdentity, actix_web::Error> {
        let maybe_valid_crypto_id = Self::try_get_header_value(&headers, Cv25519Authenticator::HEADER_IDENTITY)?;
        let maybe_valid_signature = Self::try_get_header_value(&headers, Cv25519Authenticator::HEADER_SIGNATURE)?;
        let maybe_valid_signature = hex::decode(maybe_valid_signature)
            .map_err(|inner_err| actix_web::error::ErrorUnauthorized(inner_err.to_string()))?;
        let valid_identity = nagara_identities::CryptographicIdentity::try_from_public_str(maybe_valid_crypto_id)
            .map_err(|inner_err| actix_web::error::ErrorUnauthorized(inner_err.to_string()))?;
        let verified_signature = valid_identity
            .verify(&maybe_valid_signature, payload_bytes)
            .map_err(|inner_err| actix_web::error::ErrorUnauthorized(inner_err.to_string()))?;

        if verified_signature {
            Ok(valid_identity)
        } else {
            Err(actix_web::error::ErrorUnauthorized(
                "Crypto identity cannot be verified!",
            ))
        }
    }

    async fn try_get_payload(
        service_request: &mut actix_web::dev::ServiceRequest,
    ) -> core::result::Result<actix_web::web::Bytes, actix_web::Error> {
        let mut request_body = actix_web::web::BytesMut::new();
        let (_, mut original_payload) = actix_http::h1::Payload::create(true);

        while let Some(chunk) = service_request.take_payload().next().await {
            request_body.extend_from_slice(&chunk?);
        }

        original_payload.unread_data(request_body.clone().freeze());
        service_request.set_payload(actix_web::dev::Payload::from(original_payload));

        if request_body.is_empty() {
            Ok(actix_web::web::Bytes::from_static(&Cv25519Authenticator::EMPTY_PAYLOAD))
        } else {
            Ok(request_body.into())
        }
    }
}

impl<S, Req> actix_web::dev::Service<actix_web::dev::ServiceRequest> for Cv25519AuthenticatorService<S>
where
    S: actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse<Req>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
    S: 'static,
{
    type Error = S::Error;
    type Future = core::pin::Pin<
        alloc::boxed::Box<dyn futures::Future<Output = core::result::Result<Self::Response, Self::Error>>>,
    >;
    type Response = actix_web::dev::ServiceResponse<Req>;

    actix_web::dev::forward_ready!(wrapped_service);

    fn call(&self, mut service_request: actix_web::dev::ServiceRequest) -> Self::Future {
        let headers = service_request.headers().clone();
        let wrapped_service_clone = self.wrapped_service.clone();

        alloc::boxed::Box::pin(async move {
            let payload_bytes = Self::try_get_payload(&mut service_request).await?;
            let verified_crypto_id = Self::try_get_verified_identity_from_headers(headers, &payload_bytes)?;
            service_request.extensions_mut().insert(verified_crypto_id);
            let service_promise = wrapped_service_clone.call(service_request);
            let service_result = service_promise.await?;

            Ok(service_result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_http::body::MessageBody;
    use actix_http::header::{HeaderName, HeaderValue};
    use actix_web::http::StatusCode;
    use actix_web::test::{init_service, try_call_service, TestRequest};
    use actix_web::web::ReqData;
    use actix_web::{get, App, Responder};
    use nagara_identities::CryptographicIdentity;
    use sp_core::ed25519::Pair as Ed25519KeyPair;
    use sp_core::sr25519::Pair as Sr25519KeyPair;
    use sp_core::Pair;

    const ALICE_SECRET_SEED: &str = "0xe5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a";
    const ALICE_SR25519_IDENTITY: &str = "gr5wupneKLGRBrA3hkcrXgbwXp1F26SV7L4LymGxCKs9QMXn1";
    const ALICE_ED25519_IDENTITY: &str = "gr2LLpGt2rLUixu5YzrWNvbX9qJeavgZLh95UpwBpvZSq6xpA";

    #[get("/")]
    async fn mock_get_docroot(verified_crypto_id: Option<ReqData<CryptographicIdentity>>) -> impl Responder {
        if let Some(crypto_id) = verified_crypto_id {
            let public_key = if crypto_id.is_schnorrkel() {
                crypto_id.try_get_public_sr25519().unwrap()
            } else {
                crypto_id.try_get_public_ed25519().unwrap()
            };

            public_key.to_string()
        } else {
            "".to_owned()
        }
    }

    #[actix_rt::test]
    async fn missing_header_id_yield_unauthorized() {
        let test_service = init_service(App::new().wrap(Cv25519Authenticator).service(mock_get_docroot)).await;
        let mut test_request = TestRequest::with_uri("/").to_request();
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_SIGNATURE),
            HeaderValue::from_static("0xsomebadsignature"),
        );
        let test_response = try_call_service(&test_service, test_request).await;

        assert!(test_response.is_err());
        assert_eq!(
            test_response.unwrap_err().error_response().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_rt::test]
    async fn missing_header_signature_yield_unauthorized() {
        let test_service = init_service(App::new().wrap(Cv25519Authenticator).service(mock_get_docroot)).await;
        let mut test_request = TestRequest::with_uri("/").to_request();
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_IDENTITY),
            HeaderValue::from_static(ALICE_SR25519_IDENTITY),
        );
        let test_response = try_call_service(&test_service, test_request).await;

        assert!(test_response.is_err());
        assert_eq!(
            test_response.unwrap_err().error_response().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[actix_rt::test]
    async fn alice_sr25519_can_be_verified() {
        let alice_keypair = Sr25519KeyPair::from_string(ALICE_SECRET_SEED, None).unwrap();
        let alice_signature = alice_keypair.sign(&Cv25519Authenticator::EMPTY_PAYLOAD).0;
        let alice_signature = hex::encode(alice_signature);
        let test_service = init_service(App::new().wrap(Cv25519Authenticator).service(mock_get_docroot)).await;
        let mut test_request = TestRequest::with_uri("/").to_request();
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_IDENTITY),
            HeaderValue::from_static(ALICE_SR25519_IDENTITY),
        );
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_SIGNATURE),
            HeaderValue::from_str(&alice_signature).unwrap(),
        );
        let test_response = try_call_service(&test_service, test_request).await;

        assert!(test_response.is_ok());

        let test_response = test_response.unwrap();
        let test_bytes_response = test_response.into_body().try_into_bytes().unwrap().to_vec();
        let test_text_response = String::from_utf8(test_bytes_response).unwrap();

        assert_eq!(&test_text_response, ALICE_SR25519_IDENTITY);
    }

    #[actix_rt::test]
    async fn alice_ed25519_can_be_verified() {
        let alice_keypair = Ed25519KeyPair::from_string(ALICE_SECRET_SEED, None).unwrap();
        let alice_signature = alice_keypair.sign(&Cv25519Authenticator::EMPTY_PAYLOAD).0;
        let alice_signature = hex::encode(alice_signature);
        let test_service = init_service(App::new().wrap(Cv25519Authenticator).service(mock_get_docroot)).await;
        let mut test_request = TestRequest::with_uri("/").to_request();
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_IDENTITY),
            HeaderValue::from_static(ALICE_ED25519_IDENTITY),
        );
        test_request.headers_mut().insert(
            HeaderName::from_static(Cv25519Authenticator::HEADER_SIGNATURE),
            HeaderValue::from_str(&alice_signature).unwrap(),
        );
        let test_response = try_call_service(&test_service, test_request).await;

        assert!(test_response.is_ok());

        let test_response = test_response.unwrap();
        let test_bytes_response = test_response.into_body().try_into_bytes().unwrap().to_vec();
        let test_text_response = String::from_utf8(test_bytes_response).unwrap();

        assert_eq!(&test_text_response, ALICE_ED25519_IDENTITY);
    }
}
