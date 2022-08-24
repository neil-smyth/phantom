/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Text;
using System.Runtime.InteropServices;

namespace Phantom;

class Program
{
    public static string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    static void Main(string[] args)
    {
        int i;
        Console.WriteLine("Hello World!");

        IntPtr keySharingObj = ShamirsSecretSharing.Create(3, 2);
        
        byte[] Key = new byte[32];
        for (i=0; i<32; i++) { Key[i] = (byte)i; }
        Console.Write("Key = ");
        for (i=0; i<32; i++) { Console.Write($"{Key[i]} "); }
        Console.WriteLine("");
        string base64Key = Convert.ToBase64String(Key);

        ShamirsSecretSharing.Split(keySharingObj, base64Key);

        int shardLength = ShamirsSecretSharing.GetShardLength();
        Console.WriteLine($"shard length is {shardLength}");

        for (i=0; i<3; i++) {
            string userShard = ShamirsSecretSharing.GetShard(keySharingObj, i);
            Console.WriteLine($"shard {i} is {userShard}");
        }


        string recoveredKey = ShamirsSecretSharing.Combine(keySharingObj);
        Console.WriteLine($"Recovered Key = {recoveredKey}");
        byte[] data = Convert.FromBase64String(recoveredKey);
        Console.Write("Decoded Key = ");
        for (i=0; i<32; i++) { Console.Write($"{data[i]} "); }
        Console.WriteLine("");

        ShamirsSecretSharing.Destroy(keySharingObj);
        Console.WriteLine("Finished");
    }
}
