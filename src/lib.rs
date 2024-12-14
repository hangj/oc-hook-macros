#![allow(non_snake_case)]

use objc2::encode::Encode;
use objc2::encode::EncodeArguments;
use objc2::encode::EncodeReturn;
use objc2::ffi::class_addMethod;
use objc2::runtime::AnyClass;
use objc2::runtime::AnyObject;
use objc2::runtime::MethodImplementation;
use objc2::runtime::Sel;
use objc2::Encoding;
use objc2::Message;

pub use objc2;
pub use ctor;

// https://github.com/MustangYM/WeChatExtension-ForMac/blob/develope/WeChatExtension/WeChatExtension/Sources/Helper/YMSwizzledHelper.m
pub fn exchange_instance_method(
    originalClass: &AnyClass,
    originalSelector: Sel,
    swizzledClass: &AnyClass,
    swizzledSelector: Sel,
) {
    let original_method = originalClass.instance_method(originalSelector);
    let swizzled_method = swizzledClass.instance_method(swizzledSelector);
    if original_method.is_some() && swizzled_method.is_some() {
        let ori = original_method.unwrap();
        let swi = swizzled_method.unwrap();
        unsafe { ori.exchange_implementation(swi) };
    }
}

pub fn exchange_class_method(
    originalClass: &AnyClass,
    originalSelector: Sel,
    swizzledClass: &AnyClass,
    swizzledSelector: Sel,
) {
    let original_method = originalClass.class_method(originalSelector);
    let swizzled_method = swizzledClass.class_method(swizzledSelector);
    if original_method.is_some() && swizzled_method.is_some() {
        let ori = original_method.unwrap();
        let swi = swizzled_method.unwrap();
        unsafe { ori.exchange_implementation(swi) };
    }
}

pub fn hook_instance_method<T, F>(cls: &AnyClass, sel: Sel, func: F)
where
    T: Message + ?Sized,
    F: MethodImplementation<Callee = T>,
{
    if cls.instance_method(sel).is_none() {
        return;
    }

    let s = format!("hook_{}", sel.name());
    let hook_sel = Sel::register(s.as_str());
    insert_method(cls, hook_sel, func);

    exchange_instance_method(cls, sel, cls, hook_sel);
}

pub fn hook_class_method<T, F>(cls: &AnyClass, sel: Sel, func: F)
where
    T: Message + ?Sized,
    F: MethodImplementation<Callee = T>,
{
    let s = format!("hook_{}", sel.name());
    let hook_sel = Sel::register(s.as_str());
    insert_method(cls.metaclass(), hook_sel, func);

    exchange_class_method(cls, sel, cls, hook_sel);
}

pub fn insert_method<T, F>(cls: &AnyClass, sel: Sel, func: F) -> bool
where
    T: Message + ?Sized,
    F: MethodImplementation<Callee = T>,
{
    fn method_type_encoding(ret: &Encoding, args: &[Encoding]) -> std::ffi::CString {
        // First two arguments are always self and the selector
        let mut types = format!("{ret}{}{}", <*mut AnyObject>::ENCODING, Sel::ENCODING);
        for enc in args {
            use core::fmt::Write;
            write!(&mut types, "{enc}").unwrap();
        }
        std::ffi::CString::new(types).unwrap()
    }

    let enc_args = F::Arguments::ENCODINGS;
    let enc_ret = &F::Return::ENCODING_RETURN;

    let sel_args = sel.name().as_bytes().iter().filter(|&&b| b == b':').count();

    assert_eq!(
        sel_args,
        enc_args.len(),
        "selector {sel} accepts {sel_args} arguments, but function accepts {}",
        enc_args.len(),
    );

    let types = method_type_encoding(enc_ret, enc_args);

    unsafe {
        let success = class_addMethod(
            cls as *const AnyClass as _,
            sel.as_ptr(),
            Some(func.__imp()),
            types.as_ptr(),
        );
        // success is a `bool` in aarch64, or is an `i8`
        success as i8 != false as i8
    }
}

#[macro_export]
macro_rules! dummy_args {
    (
        $arg:ident $(,$tail:ident)* $(,)?
    ) => {
        $crate::dummy_args! {
            [_]
            $($tail)*
        }
    };
    (
        unsafe $arg:ident $(,$tail:ident)* $(,)?
    ) => {
        $crate::dummy_args! {
            unsafe
            [_]
            $($tail)*
        }
    };

    (
        $($unsafe:ident)?
        [$($t:tt)*]
        $arg:ident $($tail:ident)*
    ) => {
        $crate::dummy_args! {
            $($unsafe)?
            [$($t)*, _]
            $($tail)*
        }
    };

    (
        $($unsafe:ident)?
        [$($t:tt)*]
    ) => {
        $($unsafe)? extern "C" fn ($($t)*) -> _
    };
}

#[macro_export]
macro_rules! arg_count {
    // for function arguments, Example: a,b,c
    (
        $arg:ident $(,$tail:ident)* $(,)?
    ) => {
        $crate::arg_count! {
            [1] $($tail)*
        }
    };

    (
        [$($t:tt)*]
        $arg:ident $($tail:ident)*
    ) => {
        $crate::arg_count! {
            [$($t)* + 1] $($tail)*
        }
    };

    () => {0};

    (
        [$($t:tt)*]
    ) => {
        $($t)*
    };
}

#[macro_export]
macro_rules! sel_count {
    // for selector, Example: WeChat:hello:world:
    (
        $arg:ident
    ) => {
        $crate::sel_count! {
            [0]
        }
    };

    (
        $arg:ident : $($tail:ident :)*
    ) => {
        $crate::sel_count! {
            [1]
            $($tail :)*
        }
    };

    (
        [$($t:tt)*]
        $arg:ident : $($tail:ident :)*
    ) => {
        $crate::sel_count! {
            [$($t)* + 1] $($tail :)*
        }
    };

    (
        [$($t:tt)*]
    ) => {
        $($t)*
    };
}

#[macro_export]
macro_rules! param_count_match {
    (
        [$($arg:ident),*]
        []
    ) => {};

    (
        [$($arg:ident),*]
        [$($sel:tt)*]
    ) => {
        $crate::param_count_match!{
            [$($arg),*]
            [$($sel)*]
            [$($sel)*]
        }
    };

    (
        [$arg1:ident $(,$tail1:ident)* $(,)?]
        [$sel:ident : $($tail2:ident :)*]
        [$($t:tt)*]
    ) => {
        $crate::param_count_match! {
            [$($tail1),*]
            [$($tail2 :)*]
            [$($t)*]
        }
    };

    (
        [$arg1:ident, $arg2:ident]
        [$($sel:ident)?]
        [$($t:tt)*]
    ) => {
        // count match
    };

    (
        [$($arg:tt)*]
        [$($sel:tt)*]
        [$($t:tt)*]
    ) => {
        compile_error!(stringify!(the param count of selector($($t)*) and function does not equal));
    };
}

/// Example:
///
/// ```
/// hook_helper! {
///     // hook a class method
///     +(void)[ClassA hello]
///     unsafe extern "C" fn(this: &NSObject, _cmd: Sel) {
///         // call the original implementation by the `hook_*` selector`
///        let _:() = msg_send![this, hook_hello];
///     }
///
///     // hokk a instance method
///     -(void)[ClassB world:]
///     unsafe extern "C" fn(this: &NSObject, _cmd: Sel, s: &NSString) {
///         // call the original implementation by the `hook_*` selector`
///         let _:() = msg_send![this, hook_world:s];
///     }
/// }
/// ```
#[macro_export]
macro_rules! hook_helper {
    (
        $(
            $(#[$meta: meta])*
            $(-($($r:tt)*)[$class1: ident $($sel1:tt)*])?
            $(+($($r2:tt)*)[$class2: ident $($sel2:tt)*])?
            unsafe extern "C" fn $name: ident ($($arg:ident: $ty: ty),* $(,)?) $(->$ret:ty)? $body: block
        )*
    ) => {
        $(
            #[allow(non_snake_case)]
            $(#[$meta])*
            unsafe extern "C" fn $name($($arg: $ty),*) $(->$ret)? $body

            #[allow(unused_imports)]
            #[allow(non_snake_case)]
            mod $name {
                use $crate::objc2::class;
                use $crate::objc2::sel;
                use super::$name;

                #[$crate::ctor::ctor]
                fn __dymmy() {
                    $crate::param_count_match!{
                        [$($arg),*]
                        [$($($sel1)*)?]
                    };

                    $crate::param_count_match!{
                        [$($arg),*]
                        [$($($sel2)*)?]
                    };

                    #[allow(unused_macros)]
                    macro_rules! func {
                        () => {
                            $crate::dummy_args!(unsafe $($arg),*)
                        };
                    }
                    $(
                        $crate::hook_instance_method(class!($class1), sel!($($sel1)*), $name as func!());
                    )?
                    $(
                        $crate::hook_class_method(class!($class2), sel!($($sel2)*), $name as func!());
                    )?
                }
            }
        )*
    };
}

#[macro_export]
macro_rules! new_selector {
    (
        $(
            $(#[$meta: meta])*
            $(-($($r:tt)*)[$class1: ident $($sel1:tt)*])?
            $(+($($r2:tt)*)[$class2: ident $($sel2:tt)*])?
            unsafe extern "C" fn $name: ident ($($arg:ident: $ty: ty),* $(,)?) $(->$ret:ty)? $body: block
        )*
    ) => {
        $(
            #[allow(non_snake_case)]
            $(#[$meta])*
            unsafe extern "C" fn $name($($arg: $ty),*) $(->$ret)? $body

            #[allow(unused_imports)]
            #[allow(non_snake_case)]
            mod $name {
                use $crate::objc2::class;
                use $crate::objc2::sel;
                use super::$name;

                #[$crate::ctor::ctor]
                fn __dymmy() {
                    $crate::param_count_match!{
                        [$($arg),*]
                        [$($($sel1)*)?]
                    };

                    $crate::param_count_match!{
                        [$($arg),*]
                        [$($($sel2)*)?]
                    };

                    #[allow(unused_macros)]
                    macro_rules! func {
                        () => {
                            $crate::dummy_args!(unsafe $($arg),*)
                        };
                    }
                    $(
                        $crate::insert_method(class!($class1), sel!($($sel1)*), $name as func!());
                    )?
                    $(
                        $crate::insert_method(class!($class2).metaclass(), sel!($($sel2)*), $name as func!());
                    )?
                }
            }
        )*
    };
}
