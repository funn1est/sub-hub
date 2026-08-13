const CONFIG_DOMAIN: &[u8] = b"sub-hub/ConfigFingerprint/SHA-256";
const EVIDENCE_DOMAIN: &[u8] = b"sub-hub/OmittedRuleEvidence/SHA-256";

pub(super) fn decode_config(input: &[u8]) -> Result<(), ()> {
    let mut decoder = Decoder::new(input);
    decoder.domain(CONFIG_DOMAIN)?;
    decoder.version()?;
    if decoder.byte()? != 1 {
        return Err(());
    }
    decoder.sequence(SelfDescribing::directive)?;
    decoder.finish()
}

pub(super) fn decode_evidence(input: &[u8]) -> Result<(), ()> {
    let mut decoder = Decoder::new(input);
    decoder.domain(EVIDENCE_DOMAIN)?;
    decoder.version()?;
    if decoder.byte()? != 1 {
        return Err(());
    }
    decoder.take(32)?;
    decoder.sequence(SelfDescribing::evidence_entry)?;
    decoder.finish()
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn finish(self) -> Result<(), ()> {
        (self.position == self.input.len()).then_some(()).ok_or(())
    }

    fn domain(&mut self, expected: &[u8]) -> Result<(), ()> {
        let length = usize::from(self.u16()?);
        if self.take(length)? == expected {
            Ok(())
        } else {
            Err(())
        }
    }

    fn version(&mut self) -> Result<(), ()> {
        (self.u16()? == 1).then_some(()).ok_or(())
    }

    fn byte(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ()> {
        let bytes = self.take(2)?.try_into().map_err(|_| ())?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ()> {
        let bytes = self.take(4)?.try_into().map_err(|_| ())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn text(&mut self) -> Result<(), ()> {
        let length = usize::try_from(self.u32()?).map_err(|_| ())?;
        std::str::from_utf8(self.take(length)?).map_err(|_| ())?;
        Ok(())
    }

    fn boolean(&mut self) -> Result<(), ()> {
        matches!(self.byte()?, 0 | 1).then_some(()).ok_or(())
    }

    fn optional_u32(&mut self) -> Result<(), ()> {
        match self.byte()? {
            0 => Ok(()),
            1 => self.u32().map(|_| ()),
            _ => Err(()),
        }
    }

    fn sequence(&mut self, decode_item: fn(&mut Self) -> Result<(), ()>) -> Result<(), ()> {
        let count = usize::try_from(self.u32()?).map_err(|_| ())?;
        for _ in 0..count {
            decode_item(self)?;
        }
        Ok(())
    }

    fn target(&mut self) -> Result<(), ()> {
        match self.byte()? {
            1 | 2 => Ok(()),
            3 => self.text(),
            _ => Err(()),
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ()> {
        let end = self.position.checked_add(length).ok_or(())?;
        let value = self.input.get(self.position..end).ok_or(())?;
        self.position = end;
        Ok(value)
    }
}

struct SelfDescribing;

impl SelfDescribing {
    fn directive(decoder: &mut Decoder<'_>) -> Result<(), ()> {
        match decoder.byte()? {
            1 => {
                decoder.target()?;
                Self::rule_source(decoder)
            }
            2 => Self::group(decoder),
            3 | 4 => decoder.boolean(),
            _ => Err(()),
        }
    }

    fn rule_source(decoder: &mut Decoder<'_>) -> Result<(), ()> {
        match decoder.byte()? {
            1 => decoder.text(),
            2 | 3 => Ok(()),
            _ => Err(()),
        }
    }

    fn group(decoder: &mut Decoder<'_>) -> Result<(), ()> {
        decoder.text()?;
        let group_type = decoder.byte()?;
        if !matches!(group_type, 1..=4) {
            return Err(());
        }
        decoder.sequence(Self::member)?;
        if group_type != 1 {
            decoder.text()?;
            decoder.u32()?;
            decoder.optional_u32()?;
        }
        Ok(())
    }

    fn member(decoder: &mut Decoder<'_>) -> Result<(), ()> {
        match decoder.byte()? {
            1 => decoder.target(),
            2 => decoder.text(),
            _ => Err(()),
        }
    }

    fn evidence_entry(decoder: &mut Decoder<'_>) -> Result<(), ()> {
        if decoder.byte()? != 1 {
            return Err(());
        }
        decoder.u32()?;
        decoder.u32()?;
        decoder.target()?;
        decoder.text()
    }
}

#[cfg(test)]
mod tests {
    use super::{CONFIG_DOMAIN, EVIDENCE_DOMAIN, decode_config, decode_evidence};
    use crate::acl4ssr::{
        Config, OmittedEvidenceEntry, TargetRef, encode_config_fingerprint, encode_omitted_evidence,
    };

    #[test]
    fn independently_decodes_encoder_coverage_and_rejects_all_truncations() {
        let config = Config::parse(
            b"[custom]\n\
              ruleset=P,https://rules.example/a\n\
              custom_proxy_group=P`url-test`[]DIRECT`a.+`https://probe.example/x`300,,50\n\
              enable_rule_generator=true\n\
              ruleset=P,[]FINAL\n\
              overwrite_original_rules=true\n",
        )
        .unwrap();
        let config_wire = encode_config_fingerprint(&config).unwrap();
        assert!(decode_config(&config_wire).is_ok());
        reject_truncations_and_trailing(&config_wire, decode_config);

        let evidence_wire = encode_omitted_evidence(
            [7; 32],
            &[OmittedEvidenceEntry {
                remote_source_ordinal: 3,
                url_regex_ordinal: 2,
                target: TargetRef::Group("P".to_owned()),
                pattern: "opaque,pattern".to_owned(),
            }],
        )
        .unwrap();
        assert!(decode_evidence(&evidence_wire).is_ok());
        reject_truncations_and_trailing(&evidence_wire, decode_evidence);
    }

    #[test]
    fn rejects_unknown_tags_invalid_flags_lengths_versions_and_utf8() {
        for body in [
            vec![0xff, 0, 0, 0, 0],
            vec![1, 0, 0, 0, 1, 0xff],
            vec![1, 0, 0, 0, 1, 3, 2],
            vec![1, 0, 0, 0, 1, 1, 0xff],
            vec![1, 0, 0, 0, 1, 1, 1, 0xff],
            vec![1, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0xff],
            vec![1, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0xff],
            vec![1, 0, 0, 0, 1, 2, 0, 0, 0, 1, 0xff],
            vec![
                1, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff,
            ],
            vec![1, 0, 0, 0, 1, 2, 0, 0, 0, 1],
        ] {
            assert!(decode_config(&stream(CONFIG_DOMAIN, 1, &body)).is_err());
        }
        assert!(decode_config(&stream(CONFIG_DOMAIN, 2, &[1, 0, 0, 0, 0])).is_err());
        assert!(decode_config(&stream(b"wrong-domain", 1, &[1, 0, 0, 0, 0])).is_err());

        let mut evidence_body = vec![1];
        evidence_body.extend_from_slice(&[0; 32]);
        evidence_body.extend_from_slice(&1_u32.to_be_bytes());
        evidence_body.extend_from_slice(&[0xff]);
        assert!(decode_evidence(&stream(EVIDENCE_DOMAIN, 1, &evidence_body)).is_err());
        evidence_body[0] = 2;
        assert!(decode_evidence(&stream(EVIDENCE_DOMAIN, 1, &evidence_body)).is_err());
    }

    fn reject_truncations_and_trailing(wire: &[u8], decode: fn(&[u8]) -> Result<(), ()>) {
        for length in 0..wire.len() {
            assert!(decode(&wire[..length]).is_err(), "accepted length {length}");
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    fn stream(domain: &[u8], version: u16, body: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&u16::try_from(domain.len()).unwrap().to_be_bytes());
        output.extend_from_slice(domain);
        output.extend_from_slice(&version.to_be_bytes());
        output.extend_from_slice(body);
        output
    }
}
