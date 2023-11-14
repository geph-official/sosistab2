// Constants
const LOW_WINDOW: f64 = 38.0;
const HIGH_WINDOW: f64 = 83000.0;
const LOW_P: f64 = 1e-3;
const HIGH_P: f64 = 1e-3;
const HIGH_DECREASE: f64 = 0.1;

fn s() -> f64 {
    (HIGH_WINDOW.log2() - LOW_WINDOW.log10()) / (HIGH_P.log10() - LOW_P.log10())
}

pub fn beta(w: f64) -> f64 {
    if w <= LOW_WINDOW {
        0.5
    } else if w >= HIGH_WINDOW {
        HIGH_DECREASE
    } else {
        // Linear interpolation between Low_Window and High_Window
        (HIGH_DECREASE - 0.5) * (w.log10() - LOW_WINDOW.log10())
            / (HIGH_WINDOW.log10() - LOW_WINDOW.log10())
            + 0.5
    }
}

pub fn alpha(w: f64) -> f64 {
    if w <= LOW_WINDOW {
        1.0
    } else {
        // Calculate packet drop rate p(w) for the current window size
        let p_w: f64 = (LOW_WINDOW / w).powf(1.0 / s()) * LOW_P;
        // Calculate a(w) using p(w) and b(w)
        w.powf(2.0) * p_w * 2.0 * beta(w) / (2.0 - beta(w))
    }
}
