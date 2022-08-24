/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Runtime.InteropServices;

namespace Phantom;

public static class BuildInfo
{

    [StructLayout(LayoutKind.Sequential)]
    public struct csss {
        IntPtr Fpe;
        IntPtr Map;
        int MaxIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ShamirsContext {}

    [DllImport("libphantom.so", EntryPoint = "build_version", CallingConvention = CallingConvention.Cdecl)]
    public static extern string Version();

    [DllImport("libphantom.so", EntryPoint = "build_datetime", CallingConvention = CallingConvention.Cdecl)]
    public static extern string BuildDate();

    [DllImport("libphantom.so", EntryPoint = "build_compiler", CallingConvention = CallingConvention.Cdecl)]
    public static extern string Compiler();

}

