# Usage

```rs
use oc_hook_macros::*;

hook_helper! {
    // hook instance method
    - (void) [NSApplication run]
    unsafe extern "C" fn hook_run(_this: &NSObject, _cmd: Sel) {
        log::error!("hook_run, bye bye");
    }

    // hook class method
    +(id)[ClassA hello]
    unsafe extern "C" fn hello(this: &NSObject, _cmd: Sel) -> *mut NSObject{
        // call the original method by the hooked selector which starts with `hook_`
        let ret: Retained<NSObject> msg_send_id![this, hook_hello];
        Retained::into_raw(ret)
    }
}

// insert new method into existing class
new_selector! {
    -(void)[NSObject openNewXXInstace:]
    unsafe extern "C" fn openNewXXInstace(_this:&NSObject, _cmd: Sel, _sender: *mut NSObject) {
        // ...
    }
}

```
