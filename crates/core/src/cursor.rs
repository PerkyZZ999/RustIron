use rustiron_contracts::{ErrorCode, Id, PageLimit};

pub(crate) fn create(
    instance: &str,
    revision: i64,
    offset: usize,
    limit: PageLimit,
) -> Result<Id, ErrorCode> {
    Id::try_from(format!(
        "{instance}{revision:016x}{offset:04x}{:04x}",
        limit.get()
    ))
    .map_err(|_| ErrorCode::DependencyUnavailable)
}

pub(crate) fn offset(
    cursor: Option<&Id>,
    instance: &str,
    revision: i64,
    limit: PageLimit,
    count: usize,
) -> Result<usize, ErrorCode> {
    let Some(cursor) = cursor else { return Ok(0) };
    let text = cursor.as_str();
    if text.len() != 56 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ErrorCode::CursorExpired);
    }
    let parse = |text: &str| u64::from_str_radix(text, 16).map_err(|_| ErrorCode::CursorExpired);
    let offset = usize::try_from(parse(&text[48..52])?).map_err(|_| ErrorCode::CursorExpired)?;
    if &text[..32] != instance
        || parse(&text[32..48])? != revision as u64
        || parse(&text[52..56])? != u64::from(limit.get())
        || offset == 0
        || offset >= count
        || offset % usize::from(limit.get()) != 0
    {
        return Err(ErrorCode::CursorExpired);
    }
    Ok(offset)
}
