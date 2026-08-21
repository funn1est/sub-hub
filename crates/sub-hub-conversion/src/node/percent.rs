use std::borrow::Cow;

pub(crate) fn decode(input: &str) -> Result<Cow<'_, str>, ()> {
    let source = input.as_bytes();
    if !source.contains(&b'%') {
        return Ok(Cow::Borrowed(input));
    }

    let mut decoded = Vec::with_capacity(source.len());
    let mut index = 0;

    while index < source.len() {
        if source[index] == b'%' {
            let high = source.get(index + 1).and_then(|byte| hex_value(*byte));
            let low = source.get(index + 2).and_then(|byte| hex_value(*byte));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(());
            };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(source[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).map(Cow::Owned).map_err(|_| ())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
