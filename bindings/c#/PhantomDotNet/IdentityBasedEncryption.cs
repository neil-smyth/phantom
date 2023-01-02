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

public enum PKC
{ 
    PKC_IBE_DLP = 0,
};

public static class IdentityBasedEncryption
{
    public enum SecurityStrength
    {
        SECURITY_STRENGTH_60 = 0,
        SECURITY_STRENGTH_80,
        SECURITY_STRENGTH_96,
        SECURITY_STRENGTH_112,
        SECURITY_STRENGTH_128,
        SECURITY_STRENGTH_160,
        SECURITY_STRENGTH_192,
        SECURITY_STRENGTH_224,
        SECURITY_STRENGTH_256,
        SECURITY_STRENGTH_288,
        SECURITY_STRENGTH_320,
    };

    [DllImport("libphantom.so", EntryPoint = "create_ibe", CallingConvention = CallingConvention.Cdecl)]
    [return : MarshalAs(UnmanagedType.SysUInt)]
    public static extern IntPtr Create(PKC Type);

    [DllImport("libphantom.so", EntryPoint = "destroy_ibe", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Destroy(IntPtr IBE);

    [DllImport("libphantom.so", EntryPoint = "create_ibe_ctx", CallingConvention = CallingConvention.Cdecl)]
    [return : MarshalAs(UnmanagedType.SysUInt)]
    public static extern IntPtr CreateCtx(IntPtr IBE, SecurityStrength Strength);

    [DllImport("libphantom.so", EntryPoint = "destroy_ibe_ctx", CallingConvention = CallingConvention.Cdecl)]
    public static extern void DestroyCtx(IntPtr IBE);

    [DllImport("libphantom.so", EntryPoint = "ibe_gen_master_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool GenMasterKey(IntPtr IBE, IntPtr Ctx);

    [DllImport("libphantom.so", EntryPoint = "ibe_master_key_length", CallingConvention = CallingConvention.Cdecl)]
    public static extern int MasterKeyLength(IntPtr IBE, IntPtr Ctx);

    [DllImport("libphantom.so", EntryPoint = "ibe_load_master_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LoadMasterKey(IntPtr IBE, IntPtr Ctx, byte[] MasterKey, int Size);

    [DllImport("libphantom.so", EntryPoint = "ibe_store_master_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StoreMasterKey(IntPtr IBE, IntPtr Ctx, ref int Size);

    [DllImport("libphantom.so", EntryPoint = "ibe_load_public_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LoadPublicKey(IntPtr IBE, IntPtr Ctx, byte[] PublicKey, int Size);

    [DllImport("libphantom.so", EntryPoint = "ibe_store_public_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StorePublicKey(IntPtr IBE, IntPtr Ctx, ref int Size);

    [DllImport("libphantom.so", EntryPoint = "ibe_extract_user_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ExtractUserKey(IntPtr IBE, IntPtr Ctx,
        byte[] Id, int Id_Size,
        ref int Key_Size);
    
    [DllImport("libphantom.so", EntryPoint = "ibe_load_user_key", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LoadUserKey(IntPtr IBE, IntPtr Ctx,
        byte[] Id, int Id_Size,
        byte[] Key, int Key_Size);
    
    [DllImport("libphantom.so", EntryPoint = "ibe_encrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Encrypt(IntPtr IBE, IntPtr Ctx,
        byte[] Id, int Id_Size,
        byte[] M, int M_Size,
        ref int C_Size);
    
    [DllImport("libphantom.so", EntryPoint = "ibe_decrypt", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Decrypt(IntPtr IBE, IntPtr Ctx,
        byte[] C, int C_Size,
        ref int M_Size);
    
    [DllImport("libphantom.so", EntryPoint = "ibe_free_mem", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeMem(IntPtr p);
}


