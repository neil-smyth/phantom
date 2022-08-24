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

public static class ShamirsSecretSharing
{

    [StructLayout(LayoutKind.Sequential)]
    public struct csss {
        IntPtr Fpe;
        IntPtr Map;
        int MaxIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ShamirsContext {}

    [DllImport("libphantom.so", EntryPoint = "create_shamirs_secret_sharing", CallingConvention = CallingConvention.Cdecl)]
    [return : MarshalAs(UnmanagedType.SysUInt)]
    public static extern IntPtr Create(int n, int k);

    [DllImport("libphantom.so", EntryPoint = "destroy_shamirs_secret_sharing", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Destroy(IntPtr KeySharing);

    [DllImport("libphantom.so", EntryPoint = "get_key_length", CallingConvention = CallingConvention.Cdecl)]
    public static extern int GetKeyLength();

    [DllImport("libphantom.so", EntryPoint = "get_shard_length", CallingConvention = CallingConvention.Cdecl)]
    public static extern int GetShardLength();

    [DllImport("libphantom.so", EntryPoint = "clear_shards", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ClearShards(IntPtr KeySharing);

    [DllImport("libphantom.so", EntryPoint = "add_shard", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool AddShard(IntPtr KeySharing, string shard, int len);

    [DllImport("libphantom.so", EntryPoint = "get_shard", CallingConvention = CallingConvention.Cdecl)]
    public static extern string GetShard(IntPtr KeySharing, int Index);

    [DllImport("libphantom.so", EntryPoint = "shamirs_secret_sharing_split", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool Split(IntPtr KeySharing, string Key);
    
    [DllImport("libphantom.so", EntryPoint = "shamirs_secret_sharing_combine", CallingConvention = CallingConvention.Cdecl)]
    public static extern string Combine(IntPtr KeySharing);
}

