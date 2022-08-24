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

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello World!");

        Random rnd = new Random();

        IntPtr fpeObj = FormatPreservingEncryption.FpeCreate();

        byte[] UserKeyBytes = new byte[16];
        rnd.NextBytes(UserKeyBytes);
        Console.WriteLine($"{UserKeyBytes[0]} {UserKeyBytes[1]} {UserKeyBytes[2]} {UserKeyBytes[3]}");

        byte[] TweakBytes = new byte[0];

        FormatPreservingEncryption.FpeContext fpeCtx;
        FormatPreservingEncryption.FpeCreateCtx(fpeObj, ref fpeCtx, UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);

        FormatPreservingEncryption.FpeKeyCacheAdd(fpeObj, "MasterKey.Organization.Format.Version", UserKeyBytes, UserKeyBytes.Length,
            FormatPreservingEncryption.FpeTypeEnum.AES_FF1_128, FormatPreservingEncryption.FpeFormatEnum.FPE_STR_ALPHANUMERIC,
            TweakBytes, TweakBytes.Length);

        string[] arrStr = {"Hello, my name is Neil Smyth! - How are you @ the moment?!",
                            "Hello, my name is Neil Smyth! - How are you @ the moment?!",
                            "Hello",
                            "Neil Smyth"};
        FormatPreservingEncryption.FpeEncryptString(fpeObj, true, ref fpeCtx, arrStr, arrStr.Length);
        foreach (var item in arrStr) {
            Console.WriteLine($"{item}");
        }

        string[] arrStr2 = {"Hello, my name is Neil Smyth! - How are you @ the moment?!",
                            "Hello, my name is Neil Smyth! - How are you @ the moment?!",
                            "Hello",
                            "Neil Smyth"};
        FormatPreservingEncryption.FpeCacheEncryptString(fpeObj, true, "MasterKey.Organization.Format.Version", arrStr2, arrStr2.Length);
        foreach (var item in arrStr2) {
            Console.WriteLine($"{item}");
        }

        FormatPreservingEncryption.FpeEncryptString(fpeObj, false, ref fpeCtx, arrStr, arrStr.Length);
        foreach (var item in arrStr) {
            Console.WriteLine($"{item}");
        }

        string[] arrStr3 = {"2021-01-01T00:00:00Z"};
        FormatPreservingEncryption.FpeCacheEncryptISO8601(fpeObj, true, "MasterKey.Organization.Format.Version", arrStr3, arrStr3.Length);
        foreach (var item in arrStr3) {
            Console.WriteLine($"{item}");
        }
        FormatPreservingEncryption.FpeCacheEncryptISO8601(fpeObj, false, "MasterKey.Organization.Format.Version", arrStr3, arrStr3.Length);
        foreach (var item in arrStr3) {
            Console.WriteLine($"{item}");
        }

        FormatPreservingEncryption.FpeDestroy(fpeObj);
    }
}
