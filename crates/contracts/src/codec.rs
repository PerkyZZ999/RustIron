use std::{collections::BTreeSet, fmt, marker::PhantomData};

use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;

use crate::{
    ApiError, Id, MAX_JSON_DEPTH, MAX_PAGE_SIZE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PageLimit,
    ProtocolError, ReadCommand, ReadData, Request, Response, SchemaVersion,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest<'a> {
    schema_version: u16,
    request_id: Id,
    method: Method,
    #[serde(borrow)]
    params: &'a RawValue,
}

#[derive(Serialize)]
struct OutgoingRequest<'a, T> {
    schema_version: SchemaVersion,
    request_id: &'a Id,
    method: &'static str,
    params: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Method {
    Doctor,
    SiteList,
    SiteInspect,
    OperationStatus,
    EvidenceExport,
    HostSummary,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorParams {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    cursor: Option<Id>,
    limit: PageLimit,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InspectParams {
    site_id: Id,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusParams {
    operation_id: Id,
}

#[derive(Deserialize)]
struct WireResponse<'a> {
    schema_version: u16,
    #[serde(borrow)]
    request_id: &'a RawValue,
    status: Status,
    #[serde(borrow)]
    data: &'a RawValue,
    #[serde(borrow)]
    error: &'a RawValue,
}

#[derive(Serialize)]
struct OutgoingResponse<'a> {
    schema_version: SchemaVersion,
    request_id: &'a Option<Id>,
    status: &'static str,
    data: Option<&'a ReadData>,
    error: Option<&'a ApiError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Error,
}

/// Decodes one bounded request, rejecting duplicate fields before typed parsing.
///
/// This performs no socket I/O or authorization. Frame/deadline/peer enforcement
/// belongs to the listener. These bytes are not a canonical signed-plan format.
pub fn decode_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let wire: WireRequest<'_> = parse(bytes)?;
    SchemaVersion::try_from(wire.schema_version).map_err(|_| ProtocolError::UnsupportedVersion)?;
    if !wire.params.get().starts_with('{') {
        return Err(ProtocolError::InvalidMessage);
    }
    let command = match wire.method {
        Method::Doctor => {
            parse::<DoctorParams>(wire.params.get().as_bytes())?;
            ReadCommand::Doctor
        }
        Method::SiteList => {
            let params: ListParams = parse(wire.params.get().as_bytes())?;
            ReadCommand::SiteList {
                cursor: params.cursor,
                limit: params.limit,
            }
        }
        Method::SiteInspect => {
            let params: InspectParams = parse(wire.params.get().as_bytes())?;
            ReadCommand::SiteInspect {
                site_id: params.site_id,
            }
        }
        Method::OperationStatus => {
            let params: StatusParams = parse(wire.params.get().as_bytes())?;
            ReadCommand::OperationStatus {
                operation_id: params.operation_id,
            }
        }
        Method::EvidenceExport => {
            let params: StatusParams = parse(wire.params.get().as_bytes())?;
            ReadCommand::EvidenceExport {
                operation_id: params.operation_id,
            }
        }
        Method::HostSummary => {
            parse::<DoctorParams>(wire.params.get().as_bytes())?;
            ReadCommand::HostSummary
        }
    };
    Ok(Request {
        request_id: wire.request_id,
        command,
    })
}

/// Serializes a validated read request with stable envelope order.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, ProtocolError> {
    fn encode<T: Serialize>(
        request: &Request,
        method: &'static str,
        params: T,
    ) -> Result<Vec<u8>, ProtocolError> {
        let wire = OutgoingRequest {
            schema_version: SchemaVersion::V1,
            request_id: &request.request_id,
            method,
            params,
        };
        serialize(&wire, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)
    }
    match &request.command {
        ReadCommand::Doctor => encode(request, "doctor", DoctorParams {}),
        ReadCommand::SiteList { cursor, limit } => encode(
            request,
            "site_list",
            ListParams {
                cursor: cursor.clone(),
                limit: *limit,
            },
        ),
        ReadCommand::SiteInspect { site_id } => encode(
            request,
            "site_inspect",
            InspectParams {
                site_id: site_id.clone(),
            },
        ),
        ReadCommand::OperationStatus { operation_id } => encode(
            request,
            "operation_status",
            StatusParams {
                operation_id: operation_id.clone(),
            },
        ),
        ReadCommand::EvidenceExport { operation_id } => encode(
            request,
            "evidence_export",
            StatusParams {
                operation_id: operation_id.clone(),
            },
        ),
        ReadCommand::HostSummary => encode(request, "host_summary", DoctorParams {}),
    }
}

/// Decodes a bounded response, tolerating additive fields but not duplicates.
///
/// Status and the null/data/error slots must agree. Callers still match the
/// request ID and successful data kind to their outstanding request.
pub fn decode_response(bytes: &[u8]) -> Result<Response, ProtocolError> {
    validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::ResponseTooLarge)?;
    let wire: WireResponse<'_> = parse(bytes)?;
    SchemaVersion::try_from(wire.schema_version).map_err(|_| ProtocolError::UnsupportedVersion)?;
    let request_id: Option<Id> = parse(wire.request_id.get().as_bytes())?;
    let result = match wire.status {
        Status::Ok if wire.error.get() == "null" && wire.data.get().starts_with('{') => {
            let data: ReadData = parse(wire.data.get().as_bytes())?;
            Ok(data)
        }
        Status::Error if wire.data.get() == "null" && wire.error.get().starts_with('{') => {
            let error: ApiError = parse(wire.error.get().as_bytes())?;
            Err(error)
        }
        _ => return Err(ProtocolError::InvalidMessage),
    };
    let response = Response { request_id, result };
    validate_response(&response)?;
    Ok(response)
}

/// Emits exactly one bounded success/error payload and the required null slot.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    validate_response(response)?;
    let (status, data, error) = match &response.result {
        Ok(data) => ("ok", Some(data), None),
        Err(error) => ("error", None, Some(error)),
    };
    serialize(
        &OutgoingResponse {
            schema_version: SchemaVersion::V1,
            request_id: &response.request_id,
            status,
            data,
            error,
        },
        MAX_RESPONSE_BYTES,
        ProtocolError::ResponseTooLarge,
    )
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)
}

// Serde structs can otherwise accept positional sequences. Our JSON records
// are named objects so field order cannot change their meaning.
pub(crate) fn object<'de, D, T>(decoder: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a named JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(ObjectVisitor(PhantomData))
}

pub(crate) fn object_list<'de, D, T>(decoder: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let objects = Vec::<Object<T>>::deserialize(decoder)?;
    Ok(objects.into_iter().map(|object| object.0).collect())
}

struct Object<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        object(decoder).map(Self)
    }
}

pub(crate) fn optional_object<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<Object<T>>::deserialize(decoder).map(|value| value.map(|object| object.0))
}

/// A member that may be absent (with `#[serde(default)]`) but is never
/// `null` when present: an explicit `null` is a decode error, not absence.
pub(crate) fn present<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(decoder).map(Some)
}

/// [`present`] for a named object member.
pub(crate) fn present_object<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    object(decoder).map(Some)
}

fn serialize<T: Serialize>(
    value: &T,
    limit: usize,
    too_large: ProtocolError,
) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidMessage)?;
    if bytes.len() > limit {
        return Err(too_large);
    }
    Ok(bytes)
}

pub(crate) fn validate_response(response: &Response) -> Result<(), ProtocolError> {
    match &response.result {
        Ok(data) => {
            if response.request_id.is_none() {
                return Err(ProtocolError::InvalidMessage);
            }
            if let ReadData::SiteList(page) = data
                && page.items.len() > usize::from(MAX_PAGE_SIZE)
            {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        Err(error) if !error.is_bounded_read_error() => return Err(ProtocolError::InvalidMessage),
        Err(_) => {}
    }
    Ok(())
}

pub(crate) fn validate_json(
    bytes: &[u8],
    limit: usize,
    too_large: ProtocolError,
) -> Result<(), ProtocolError> {
    validate_shape(bytes, limit, too_large, false)
}

pub(crate) fn validate_canonical_json(bytes: &[u8]) -> Result<(), ProtocolError> {
    validate_shape(
        bytes,
        MAX_REQUEST_BYTES,
        ProtocolError::RequestTooLarge,
        true,
    )
}

fn validate_shape(
    bytes: &[u8],
    limit: usize,
    too_large: ProtocolError,
    unsigned_integers: bool,
) -> Result<(), ProtocolError> {
    if bytes.len() > limit {
        return Err(too_large);
    }
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(ProtocolError::InvalidMessage);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    JsonShape {
        depth: 0,
        unsigned_integers,
    }
    .deserialize(&mut decoder)
    .map_err(|_| ProtocolError::InvalidMessage)?;
    decoder.end().map_err(|_| ProtocolError::InvalidMessage)
}

// Validate keys before any serde buffering can discard duplicate members.
// The payload byte ceiling bounds key-set allocation; no generic value tree is built.
struct JsonShape {
    depth: usize,
    unsigned_integers: bool,
}

impl<'de> DeserializeSeed<'de> for JsonShape {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonShape {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON with unique object members")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        if self.unsigned_integers {
            return Err(de::Error::custom("unsigned exact integer required"));
        }
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<(), E> {
        if self.unsigned_integers && value > 9_007_199_254_740_991 {
            return Err(de::Error::custom("integer exceeds exact range"));
        }
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        if self.unsigned_integers {
            return Err(de::Error::custom("unsigned exact integer required"));
        }
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON depth limit exceeded"));
        }
        while values
            .next_element_seed(JsonShape {
                depth: self.depth + 1,
                unsigned_integers: self.unsigned_integers,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON depth limit exceeded"));
        }
        let mut keys = BTreeSet::new();
        while let Some(key) = values.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON member"));
            }
            values.next_value_seed(JsonShape {
                depth: self.depth + 1,
                unsigned_integers: self.unsigned_integers,
            })?;
        }
        Ok(())
    }
}
