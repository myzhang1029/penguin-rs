macro_rules! impl_by_delegate {
    ($(
        $(#[$outer:meta])*
        $vis:vis $([$const_kw:tt])? fn $fname:ident$(<$($generic:ident $(: $($trait_bound:path)+)?),*>)?(
            $self_ty:ty $(, $arg_name:ident: $arg_ty:ty)*
        ) $(-> $ret:ty)?
    )+) => {
        $(
            $(#[$outer])*
            $vis $($const_kw)? fn $fname$(<$($generic $(: $($trait_bound +)+)?),*>)?(
                self: $self_ty
                $(, $arg_name: $arg_ty)*
            ) $(-> $ret)? {
                match self {
                    Self::Temporary(data) => data.$fname($($arg_name),*),
                    Self::Static(bytes) => bytes.$fname($($arg_name),*),
                }
            }
        )+
    };

    ($(
        $(#[$trait_outer:meta])*
        impl $trait_name:path {
            $($(#[$outer:meta])*
            fn $fname:ident$(<$($generic:ident $(: $($trait_bound:path)+)?),*>)?(
                $self_ty:ty $(, $arg_name:ident: $arg_ty:ty)*
            ) $(-> $ret:ty)?)+
        })+
    ) => {
        $(
            $(#[$trait_outer])*
            #[automatically_derived]
            impl $trait_name for crate::CowBytes<'_> {
                impl_by_delegate! {
                    $(
                        $(#[$outer])*
                        fn $fname$(<$($generic $(: $($trait_bound)+)?),*>)?(
                            $self_ty
                            $(, $arg_name: $arg_ty)*
                        ) $(-> $ret)?
                    )+
                }
            }
        )+
    }
}

macro_rules! impl_by_as_ref {
    ($(
        $(#[$outer:meta])*
        $vis:vis $([$const_kw:tt])? fn $fname:ident$(<$($generic:ident $(: $($trait_bound:path)+)?),*>)?(
            $self_ty:ty $(,[$other:ident])? $(, $arg_name:ident: $arg_ty:ty)*
        ) $(-> $ret:ty)?
    )+) => {
        $(
            $(#[$outer])*
            $vis $($const_kw)? fn $fname$(<$($generic $(: $($trait_bound +)+)?),*>)?(
                self: $self_ty
                $(, $other: $self_ty)?
                $(, $arg_name: $arg_ty)*
            ) $(-> $ret)? {
                self.as_ref().$fname($($other.as_ref(),)? $($arg_name),*)
            }
        )+
    };

    ($(
        $(#[$trait_outer:meta])*
        impl $trait_name:path {
            $($(#[$outer:meta])*
            fn $fname:ident$(<$($generic:ident $(: $($trait_bound:path)+)?),*>)?(
                $self_ty:ty $(,[$other:ident])? $(, $arg_name:ident: $arg_ty:ty)*
            ) $(-> $ret:ty)?)+
        }
    )+) => {
        $(
            $(#[$trait_outer])*
            #[automatically_derived]
            impl $trait_name for crate::CowBytes<'_> {
                impl_by_as_ref! {
                    $(
                        $(#[$outer])*
                        fn $fname$(<$($generic $(: $($trait_bound)+)?),*>)?(
                            $self_ty
                            $(, [$other])?
                            $(, $arg_name: $arg_ty)*) $(-> $ret)?
                    )+
                }
            }
        )+
    }
}

pub(crate) use {impl_by_as_ref, impl_by_delegate};
