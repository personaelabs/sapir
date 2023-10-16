use ark_std::end_timer;
use ark_std::perf_trace::inner::TimerInfo as ArkTimerInfo;
#[cfg(not(target_arch = "wasm32"))]
use ark_std::start_timer;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys;

// Struct returned by `timer_start` and passed to `timer_end`
// when compiled to `wasm32`
pub struct WebTimerInfo {
    start_time: f64,
    label: &'static str,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

// Enum returned by `timer_start` and passed to `timer_end`
pub enum TimerInfo {
    #[allow(dead_code)]
    Web(WebTimerInfo),
    #[allow(dead_code)]
    Cmd(ArkTimerInfo),
}

// Start a timer.
#[allow(dead_code)]
pub fn timer_start(label: &'static str) -> TimerInfo {
    #[cfg(target_arch = "wasm32")]
    {
        TimerInfo::Web(WebTimerInfo {
            start_time: now(),
            label,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        TimerInfo::Cmd(start_timer!(|| label))
    }
}

// End a timer and print the time elapsed.
#[allow(dead_code)]
pub fn timer_end(timer: TimerInfo) {
    match timer {
        TimerInfo::Web(t) => {
            let end = now();
            // Compute the time elapsed in milliseconds
            let duration = end - t.start_time as f64;
            web_sys::console::log_1(&JsValue::from(format!("{}: {}ms", t.label, duration)));
            // We don't use console::log_time because it doesn't work on mobile.
        }
        TimerInfo::Cmd(t) => {
            end_timer!(t);
        }
    };
}

// Profiler is just a wrapper around timer.
// The only difference is that the time measured by a profiler
// is only rendered when the feature "profiler" is enabled .
// This is useful for embedding multiple timers in a function,
// but only rendering the time when necessary.
pub struct ProfilerInfo(Option<TimerInfo>);

pub fn profiler_start(_label: &'static str) -> ProfilerInfo {
    #[cfg(feature = "profiler")]
    {
        ProfilerInfo(Some(timer_start(_label)))
    }

    #[cfg(not(feature = "profiler"))]
    {
        ProfilerInfo(None)
    }
}

pub fn profiler_end(_profiler: ProfilerInfo) {
    #[cfg(feature = "profiler")]
    timer_end(_profiler.0.unwrap())
}
