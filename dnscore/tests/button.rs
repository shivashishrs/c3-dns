use dnscore::button::{Hold, DEBOUNCE_MS, HOLD_MS};

/// Feed `pressed` every `step` ms from `from` to `to` (exclusive); return the times it fired.
fn run(h: &mut Hold, pressed: bool, from: u64, to: u64, step: u64) -> Vec<u64> {
    let mut fired = Vec::new();
    let mut t = from;
    while t < to {
        if h.sample(pressed, t) {
            fired.push(t);
        }
        t += step;
    }
    fired
}

#[test]
fn five_second_hold_fires_once() {
    let mut h = Hold::default();
    assert!(run(&mut h, false, 0, 1000, 50).is_empty());
    let fired = run(&mut h, true, 1000, 12_000, 50);
    assert_eq!(fired.len(), 1, "fires exactly once per hold: {fired:?}");
    assert!(fired[0] >= 1000 + HOLD_MS && fired[0] <= 1000 + HOLD_MS + DEBOUNCE_MS + 50, "{fired:?}");
}

#[test]
fn shorter_hold_does_nothing() {
    let mut h = Hold::default();
    assert!(run(&mut h, true, 0, HOLD_MS - 100, 50).is_empty());
    assert!(run(&mut h, false, HOLD_MS - 100, 20_000, 50).is_empty());
    // two 3 s holds with a real release between them do not add up
    let mut h = Hold::default();
    assert!(run(&mut h, true, 0, 3000, 50).is_empty());
    assert!(run(&mut h, false, 3000, 3500, 50).is_empty());
    assert!(run(&mut h, true, 3500, 6500, 50).is_empty());
}

#[test]
fn bounce_shorter_than_debounce_does_not_reset_the_hold() {
    let mut h = Hold::default();
    let mut fired = run(&mut h, true, 0, 2000, 10);
    // 20 ms glitch to "released" (contact bounce)
    fired.extend(run(&mut h, false, 2000, 2020, 10));
    fired.extend(run(&mut h, true, 2020, 6000, 10));
    assert_eq!(fired.len(), 1, "{fired:?}");
    // a bounce at the start is not a press either
    let mut h = Hold::default();
    assert!(run(&mut h, true, 0, 20, 10).is_empty());
    assert!(run(&mut h, false, 20, 10_000, 10).is_empty());
}

#[test]
fn second_hold_fires_again_after_release_and_clock_is_saturating() {
    let mut h = Hold::default();
    assert_eq!(run(&mut h, true, 0, 6000, 50).len(), 1);
    assert!(run(&mut h, false, 6000, 7000, 50).is_empty());
    assert_eq!(run(&mut h, true, 7000, 13_000, 50).len(), 1);
    // a clock going backwards never panics or fires by itself
    let mut h = Hold::default();
    assert!(!h.sample(true, 10_000));
    assert!(!h.sample(true, 5));
    assert!(!h.sample(true, 0));
}
