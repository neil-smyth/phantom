/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Runtime.InteropServices;

namespace Phantom;

public static class FormatPreservingEncryption
{
    public enum FpeTypeEnum
    { 
        AES_FF1_128 = 0,
        AES_FF1_192,
        AES_FF1_256,
        AES_FF3_1_128,
        AES_FF3_1_192,
        AES_FF3_1_256
    };

    public enum FpeFormatEnum
    {
        FPE_STR_NUMERIC = 0,
        FPE_STR_ALPHANUMERIC,
        FPE_STR_LOWER_ALPHANUMERIC,
        FPE_STR_UPPER_ALPHANUMERIC,
        FPE_STR_ALPHABETICAL,
        FPE_STR_LOWER_ALPHABETICAL,
        FPE_STR_UPPER_ALPHABETICAL,
        FPE_STR_ASCII_PRINTABLE,
        FPE_STR_UTF8,
        FPE_STR_UTF16,
        FPE_NUMBER_INT,
        FPE_NUMBER_FLOAT,
        FPE_ISO8601,
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct cfpe {
        IntPtr Fpe;
        IntPtr Map;
        int MaxIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FpeContext {}

    [DllImport("libphantom.so", EntryPoint = "create_fpe", CallingConvention = CallingConvention.Cdecl)]
    [return : MarshalAs(UnmanagedType.SysUInt)]
    public static extern IntPtr FpeCreate();

    [DllImport("libphantom.so", EntryPoint = "destroy_fpe", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FpeDestroy(IntPtr FPE);

    [DllImport("libphantom.so", EntryPoint = "create_fpe_ctx", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FpeCreateCtx(IntPtr FPE, ref FpeContext Ctx, byte[] UserKey, int UserKeySize,
        FpeTypeEnum Type, FpeFormatEnum Format, byte[] Tweak, int TweakSize);

    [DllImport("libphantom.so", EntryPoint = "cache_fpe_key_add", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FpeKeyCacheAdd(IntPtr FPE, string CacheKey, byte[] UserKey, int UserKeySize,
        FpeTypeEnum Type, FpeFormatEnum Format, byte[] Tweak, int TweakSize);

    [DllImport("libphantom.so", EntryPoint = "cache_fpe_key_remove", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FpeKeyCacheRemove(IntPtr FPE, string CacheKey);

    [DllImport("libphantom.so", EntryPoint = "fpe_encrypt_str", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeEncryptString(
        IntPtr FPE, bool EncryptFlag, ref FpeContext FPEKeyCtx, [In, Out] string[] InOut, int Size);

    [DllImport("libphantom.so", EntryPoint = "fpe_encrypt_number", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeEncryptNumber(
        IntPtr FPE, bool EncryptFlag, ref FpeContext FPEKeyCtx, [In, Out] int[] InOut, int Size, int Range);

    [DllImport("libphantom.so", EntryPoint = "fpe_encrypt_float", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeEncryptFloat(
        IntPtr FPE, bool EncryptFlag, ref FpeContext FPEKeyCtx, [In, Out] double[] InOut, int Size,
        int Range, int Precision);

    [DllImport("libphantom.so", EntryPoint = "fpe_encrypt_iso8601", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeEncryptISO8601(
        IntPtr FPE, bool EncryptFlag, ref FpeContext FPEKeyCtx, [In, Out] string[] InOut, int Size);

    [DllImport("libphantom.so", EntryPoint = "fpe_cache_encrypt_str", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeCacheEncryptString(
        IntPtr FPE, bool EncryptFlag, string CacheKey, [In, Out] string[] InOut, int Size);

    [DllImport("libphantom.so", EntryPoint = "fpe_cache_encrypt_number", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeCacheEncryptNumber(
        IntPtr FPE, bool EncryptFlag, string CacheKey, [In, Out] int[] InOut, int Size, int Range);

    [DllImport("libphantom.so", EntryPoint = "fpe_cache_encrypt_float", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeCacheEncryptFloat(
        IntPtr FPE, bool EncryptFlag, string CacheKey, [In, Out] double[] InOut, int Size,
        int Range, int Precision);

    [DllImport("libphantom.so", EntryPoint = "fpe_cache_encrypt_iso8601", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool FpeCacheEncryptISO8601(
        IntPtr FPE, bool EncryptFlag, string CacheKey, [In, Out] string[] InOut, int Size);
}


