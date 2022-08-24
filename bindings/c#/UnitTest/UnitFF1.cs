/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using Xunit;
using Phantom;

namespace UnitTest;

public class UnitFF1
{
    [Fact]
    public void Create()
    {
        IntPtr obj = FormatPreservingEncryption.FpeCreate();
        Assert.True(obj != IntPtr.Zero);
    }

    [Fact]
    public void Encrypt_WithNoKey_Fails()
    {
        byte[] UserKeyBytes = new byte[16] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] TweakBytes   = new byte[0];

        IntPtr obj = FormatPreservingEncryption.FpeCreate();

        FormatPreservingEncryption.FpeContext ctx;
        
        string[] arrStr = new string[2];
        int[] arrInt = new int[2];
        double[] arrDbl = new double[2];
        
        bool success;
        success = FormatPreservingEncryption.FpeEncryptString(obj, true, ref ctx, arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptNumber(obj, true, ref ctx, arrInt, arrInt.Length, 8);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptFloat(obj, true, ref ctx, arrDbl, arrDbl.Length, 8, 0);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptISO8601(obj, true, ref ctx, arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, true, "", arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptNumber(obj, true, "", arrInt, arrInt.Length, 8);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptFloat(obj, true, "", arrDbl, arrDbl.Length, 8, 0);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptISO8601(obj, true, "", arrStr, arrStr.Length);
        Assert.False(success);
    }

    [Fact]
    public void Decrypt_WithNoKey_Fails()
    {
        byte[] UserKeyBytes = new byte[16] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] TweakBytes   = new byte[0];

        IntPtr obj = FormatPreservingEncryption.FpeCreate();

        FormatPreservingEncryption.FpeContext ctx;
        
        string[] arrStr = new string[2];
        int[] arrInt = new int[2];
        double[] arrDbl = new double[2];
        
        bool success;
        success = FormatPreservingEncryption.FpeEncryptString(obj, false, ref ctx, arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptNumber(obj, false, ref ctx, arrInt, arrInt.Length, 8);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptFloat(obj, false, ref ctx, arrDbl, arrDbl.Length, 8, 0);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeEncryptISO8601(obj, false, ref ctx, arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, false, "", arrStr, arrStr.Length);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptNumber(obj, false, "", arrInt, arrInt.Length, 8);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptFloat(obj, false, "", arrDbl, arrDbl.Length, 8, 0);
        Assert.False(success);
        success = FormatPreservingEncryption.FpeCacheEncryptISO8601(obj, false, "", arrStr, arrStr.Length);
        Assert.False(success);
    }

    [Fact]
    public void EncryptString_WithKey_EncryptsAndDecrypts()
    {
        byte[] UserKeyBytes = new byte[16] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] TweakBytes   = new byte[0];

        IntPtr obj = FormatPreservingEncryption.FpeCreate();

        FormatPreservingEncryption.FpeContext ctx;
        FormatPreservingEncryption.FpeCreateCtx(obj, ref ctx, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);

        string[] orgStr = {"0123abcdABCD", "0123456789"};
        string[] arrStr = new string[2];
        orgStr.CopyTo(arrStr, 0);
        
        bool success;
        success = FormatPreservingEncryption.FpeEncryptString(obj, true, ref ctx, arrStr, arrStr.Length);
        Assert.True(success);
        for (int i=0; i<arrStr.Count(); i++) {
            Assert.NotEqual(orgStr[i], arrStr[i]);
        }

        success = FormatPreservingEncryption.FpeEncryptString(obj, false, ref ctx, arrStr, arrStr.Length);
        Assert.True(success);
        for (int i=0; i<arrStr.Count(); i++) {
            Assert.Equal(orgStr[i], arrStr[i]);
        }
    }

    [Fact]
    public void EncryptString_WithAbsentCacheKey_Fails()
    {
        byte[] UserKeyBytes = new byte[16] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] TweakBytes   = new byte[0];

        IntPtr obj = FormatPreservingEncryption.FpeCreate();

        string uniqueKeyId = "Unique key string such as UUID";

        FormatPreservingEncryption.FpeContext ctx;
        FormatPreservingEncryption.FpeCreateCtx(obj, ref ctx, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);

        FormatPreservingEncryption.FpeKeyCacheAdd(obj, uniqueKeyId, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);
        
        string[] orgStr = {"0123abcdABCD", "0123456789"};
        string[] arrStr = new string[2];
        orgStr.CopyTo(arrStr, 0);
        
        bool success;
        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, true, "Bad key ID", arrStr, arrStr.Length);
        Assert.False(success);

        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, false, "Bad key ID", arrStr, arrStr.Length);
        Assert.False(success);
    }
    [Fact]
    public void EncryptString_WithCacheKey_EncryptsAndDecrypts()
    {
        byte[] UserKeyBytes = new byte[16] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        byte[] TweakBytes   = new byte[0];

        IntPtr obj = FormatPreservingEncryption.FpeCreate();

        string uniqueKeyId = "Unique key string such as UUID";

        FormatPreservingEncryption.FpeContext ctx;
        FormatPreservingEncryption.FpeCreateCtx(obj, ref ctx, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);

        FormatPreservingEncryption.FpeKeyCacheAdd(obj, uniqueKeyId, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);
        
        string[] orgStr = {"0123abcdABCD", "0123456789"};
        string[] arrStr = new string[2];
        orgStr.CopyTo(arrStr, 0);
        
        bool success;
        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, true, uniqueKeyId, arrStr, arrStr.Length);
        Assert.True(success);
        for (int i=0; i<arrStr.Count(); i++) {
            Assert.NotEqual(orgStr[i], arrStr[i]);
        }

        success = FormatPreservingEncryption.FpeCacheEncryptString(obj, false, uniqueKeyId, arrStr, arrStr.Length);
        Assert.True(success);
        for (int i=0; i<arrStr.Count(); i++) {
            Assert.Equal(orgStr[i], arrStr[i]);
        }
    }
}