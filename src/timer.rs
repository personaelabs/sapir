use ark_std::end_timer;
use ark_std::perf_trace::inner::TimerInfo as ArkTimerInfo;
#[cfg(not(target_arch = "wasm32"))]
use ark_std::start_timer;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys;

pub struct WebTimerInfo {
    start_time: f64,
    label: &'static str,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

pub enum TimerInfo {
    #[allow(dead_code)]
    Web(WebTimerInfo),
    #[allow(dead_code)]
    Cmd(ArkTimerInfo),
}

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

#[allow(dead_code)]
pub fn timer_end(timer: TimerInfo) {
    match timer {
        TimerInfo::Web(t) => {
            let end = now();
            let duration = end - t.start_time as f64;
            web_sys::console::log_1(&JsValue::from(format!("{}: {}ms", t.label, duration)));
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
