/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Phantom;

class Program
{
    public static byte[] ByteArrayLeftPad(byte[] input, byte padValue, int len)
    {
        var temp = Enumerable.Repeat(padValue, len).ToArray();
        for (var i = 0; i < input.Length; i++)
            temp[i] = input[i];
        return temp;
    }

    public static byte[] ConvertIntPtrByteArray(IntPtr p,int size)
    {
        Trace.Assert(p != IntPtr.Zero);
        byte[] byteArray = new byte[size];
        Marshal.Copy(p, byteArray, 0, size);
        IdentityBasedEncryption.FreeMem(p);
        return byteArray;
    }

    static void Main(string[] args)
    {
        // Create an IBE KDC and retrieve a master key and public key

        IntPtr ibeObjKDC = IdentityBasedEncryption.Create(PKC.PKC_IBE_DLP);
        IntPtr ibeCtxKDC = IdentityBasedEncryption.CreateCtx(ibeObjKDC, IdentityBasedEncryption.SecurityStrength.SECURITY_STRENGTH_80);

        bool MasterKeySuccess = IdentityBasedEncryption.GenMasterKey(ibeObjKDC, ibeCtxKDC);
        Trace.Assert(MasterKeySuccess == true);

        int masterKeySize = 0;
        IntPtr masterKeyPtr = IdentityBasedEncryption.StoreMasterKey(ibeObjKDC, ibeCtxKDC, ref masterKeySize);
        byte[] masterKey = ConvertIntPtrByteArray(masterKeyPtr, masterKeySize);

        int publicKeySize = 0;
        IntPtr publicKeyPtr = IdentityBasedEncryption.StorePublicKey(ibeObjKDC, ibeCtxKDC, ref publicKeySize);
        byte[] publicKey = ConvertIntPtrByteArray(publicKeyPtr, publicKeySize);

        IdentityBasedEncryption.DestroyCtx(ibeCtxKDC);
        IdentityBasedEncryption.Destroy(ibeObjKDC);


        // Recreate the KDC by loading the key pair, then extract the key pair

        IntPtr ibeObjKDC2 = IdentityBasedEncryption.Create(PKC.PKC_IBE_DLP);
        IntPtr ibeCtxKDC2 = IdentityBasedEncryption.CreateCtx(ibeObjKDC2, IdentityBasedEncryption.SecurityStrength.SECURITY_STRENGTH_80);

        IdentityBasedEncryption.LoadMasterKey(ibeObjKDC2, ibeCtxKDC2, masterKey, masterKeySize);
        IdentityBasedEncryption.LoadPublicKey(ibeObjKDC2, ibeCtxKDC2, publicKey, publicKeySize);

        string Id = "Public Identity Bob";
        byte[] IdBytes = Encoding.ASCII.GetBytes(Id);

        int userKeySize = 0;
        IntPtr userKeyPtr = IdentityBasedEncryption.ExtractUserKey(ibeObjKDC2, ibeCtxKDC2, IdBytes, IdBytes.Length, ref userKeySize);
        byte[] userKey = ConvertIntPtrByteArray(userKeyPtr, userKeySize);
        
        IdentityBasedEncryption.DestroyCtx(ibeCtxKDC2);
        IdentityBasedEncryption.Destroy(ibeObjKDC2);


        // 'Alice' encrypts a message for 'Bob' and is destroyed

        IntPtr ibeObjA = IdentityBasedEncryption.Create(PKC.PKC_IBE_DLP);
        IntPtr ibeCtxA = IdentityBasedEncryption.CreateCtx(ibeObjA, IdentityBasedEncryption.SecurityStrength.SECURITY_STRENGTH_80);

        IdentityBasedEncryption.LoadPublicKey(ibeObjKDC, ibeCtxKDC, publicKey, publicKeySize);

        string message = "My super secret message that cannot exceed n/8 bytes";
        byte[] messageBytes = ByteArrayLeftPad(Encoding.ASCII.GetBytes(message), 32, 64);
        Trace.Assert(messageBytes.Length == 64);

        int ciphertextSize = 0;
        IntPtr ciphertextPtr = IdentityBasedEncryption.Encrypt(ibeObjA, ibeCtxA, IdBytes, IdBytes.Length, messageBytes, messageBytes.Length, ref ciphertextSize);
        byte[] ciphertext = ConvertIntPtrByteArray(ciphertextPtr, ciphertextSize);

        IdentityBasedEncryption.DestroyCtx(ibeCtxA);
        IdentityBasedEncryption.Destroy(ibeObjA);


        // 'Bob' decrypts his message and is destroyed

        IntPtr ibeObjB = IdentityBasedEncryption.Create(PKC.PKC_IBE_DLP);
        IntPtr ibeCtxB = IdentityBasedEncryption.CreateCtx(ibeObjB, IdentityBasedEncryption.SecurityStrength.SECURITY_STRENGTH_80);

        IdentityBasedEncryption.LoadUserKey(ibeObjB, ibeCtxB, IdBytes, IdBytes.Length, userKey, userKey.Length);

        int plaintextSize = 0;
        IntPtr plaintextPtr = IdentityBasedEncryption.Decrypt(ibeObjB, ibeCtxB, ciphertext, ciphertext.Length, ref plaintextSize);
        byte[] plaintext = ConvertIntPtrByteArray(plaintextPtr, plaintextSize);

        IdentityBasedEncryption.DestroyCtx(ibeCtxB);
        IdentityBasedEncryption.Destroy(ibeObjB);


        // Verify the message

        string recoveredMessage = Encoding.ASCII.GetString(plaintext).TrimEnd();
        Trace.Assert(recoveredMessage.Length == message.Length);
        Trace.Assert(recoveredMessage == message);
    }
}
