/*++

Module Name:

    trace.h

Abstract:

    Header file for the debug tracing functionality for the ServiceProtector driver.

Environment:

    Kernel mode

--*/

#pragma once

//
// Define the tracing flags.
//
// Tracing GUID - 2b5e7e47-3936-4f31-b7e3-f58fa344f84c
//

#define WPP_CONTROL_GUIDS                                              \
    WPP_DEFINE_CONTROL_GUID(                                           \
        ServiceProtectorTraceGuid, (2b5e7e47,3936,4f31,b7e3,f58fa344f84c), \
        WPP_DEFINE_BIT(TRACE_FLAG_GENERAL)                             \
        WPP_DEFINE_BIT(TRACE_FLAG_PROTECTION)                          \
        WPP_DEFINE_BIT(TRACE_FLAG_CALLBACKS)                           \
        WPP_DEFINE_BIT(TRACE_FLAG_IOCTL)                               \
        )                             

#define WPP_FLAG_LEVEL_LOGGER(flag, level)                                  \
    WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level)                                 \
    (WPP_LEVEL_ENABLED(flag) &&                                             \
     WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) \
           WPP_LEVEL_LOGGER(flags)
               
#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
           (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

//
// This comment block is scanned by the trace preprocessor to define our
// Trace function.
//
// begin_wpp config
// FUNC Trace{FLAG=TRACE_FLAG_GENERAL}(LEVEL, MSG, ...);
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// FUNC TraceProtection{FLAG=TRACE_FLAG_PROTECTION}(LEVEL, MSG, ...);
// FUNC TraceCallbacks{FLAG=TRACE_FLAG_CALLBACKS}(LEVEL, MSG, ...);
// FUNC TraceIOCTL{FLAG=TRACE_FLAG_IOCTL}(LEVEL, MSG, ...);
// end_wpp
//