import pandas as pd

from address_misuse.gold_final import _apply, mechanical


def test_apply_appends_note_with_plus_and_overrides_fields():
    r = pd.Series({"is_misuse": "1", "type": "T1", "note": "gốc", "confidence": "medium"})
    out = _apply(r, {"type": "T4", "note": "+ ca 7b"})
    assert out.type == "T4" and out.note == "gốc | ca 7b" and r.type == "T1"
    assert _apply(r, {"note": "thay"}).note == "thay"


def test_mechanical_reference_rule():
    items = pd.DataFrame([
        dict(item_id="a", chain="eth", address="0x1", code_at_event="none", calldata_kind="call", xc_timing="before", delegate_7702="-"),
        dict(item_id="b", chain="eth", address="0x2", code_at_event="none", calldata_kind="call", xc_timing="-", delegate_7702="-"),
        dict(item_id="c", chain="eth", address="0x3", code_at_event="none", calldata_kind="text", xc_timing="-", delegate_7702="-"),
        dict(item_id="d", chain="bsc", address="0x4", code_at_event="7702", calldata_kind="-", xc_timing="-", delegate_7702="0xD"),
        dict(item_id="e", chain="bsc", address="0x5", code_at_event="7702", calldata_kind="-", xc_timing="-", delegate_7702="0xE"),
        dict(item_id="f", chain="eth", address="0x6", code_at_event="code", calldata_kind="call", xc_timing="-", delegate_7702="-"),
        dict(item_id="g", chain="eth", address="0x7", code_at_event="unknown", calldata_kind="call", xc_timing="-", delegate_7702="0xD"),
    ])
    lookup = pd.DataFrame({"chain": ["bsc", "bsc"], "delegate": ["0xd", "0xe"], "final_class": ["forwarder_sweeper", "legit_wallet"]})
    m = mechanical(items, lookup, {"f": "0x6"}).set_index("item_id")
    assert m.mech.to_dict() == {"a": "1", "b": "1", "c": "0", "d": "1", "e": "0", "f": "1", "g": "0"}
    assert m.mech_type.to_dict() == {"a": "T4", "b": "T1", "c": "NONE", "d": "T5", "e": "NONE", "f": "T3", "g": "NONE"}
