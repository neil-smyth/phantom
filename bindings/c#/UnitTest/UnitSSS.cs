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

public class UnitSSS
{
    [Fact]
    public void Create_WithBadParameters_ReturnsNull()
    {
        IntPtr obj;
        obj = ShamirsSecretSharing.Create(0, 0);
        Assert.True(obj == IntPtr.Zero);
        obj = ShamirsSecretSharing.Create(0, 1);
        Assert.True(obj == IntPtr.Zero);
        obj = ShamirsSecretSharing.Create(1, 0);
        Assert.True(obj == IntPtr.Zero);
        obj = ShamirsSecretSharing.Create(1, 1);
        Assert.True(obj != IntPtr.Zero);
    }

    [Fact]
    public void GetKeyLength_Returns_32()
    {
        var keyLength = ShamirsSecretSharing.GetKeyLength();
        Assert.Equal(32, keyLength);
    }

    [Fact]
    public void GetShardLength_Returns_33()
    {
        var shardLength = ShamirsSecretSharing.GetShardLength();
        Assert.Equal(33, shardLength);
    }

    [Fact]
    public void GetShard_WithNoneAdded_ReturnsNull()
    {
        IntPtr obj = ShamirsSecretSharing.Create(1, 1);
        string shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.Null(shard);
    }

    [Fact]
    public void Split_WithNullKey_ReturnsFalse()
    {
        IntPtr obj = ShamirsSecretSharing.Create(1, 1);
        bool success = ShamirsSecretSharing.Split(obj, "");
        Assert.False(success);
    }

    [Fact]
    public void Split_WithKey_ReturnsTrueAndShard()
    {
        IntPtr obj = ShamirsSecretSharing.Create(1, 1);

        byte[] key = new byte[32];
        for (int i=0; i<32; i++) { key[i] = (byte)i; }
        string base64Key = Convert.ToBase64String(key);

        bool success = ShamirsSecretSharing.Split(obj, base64Key);
        Assert.True(success);

        string shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.NotNull(shard);
        
        Assert.NotEqual(shard, base64Key);
    }

    [Fact]
    public void Combine_WithNoShards_ReturnsNull()
    {
        IntPtr obj = ShamirsSecretSharing.Create(3, 2);

        byte[] key = new byte[32];
        for (int i=0; i<32; i++) { key[i] = (byte)i; }
        string base64Key = Convert.ToBase64String(key);

        bool success = ShamirsSecretSharing.Split(obj, base64Key);
        Assert.True(success);

        string shard;
        shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.NotNull(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.NotNull(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.NotNull(shard);

        ShamirsSecretSharing.ClearShards(obj);

        shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.Null(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.Null(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.Null(shard);

        string recoveredKey = ShamirsSecretSharing.Combine(obj);
        Assert.Null(recoveredKey);
    }

    [Fact]
    public void Combine_WithMinimumShards_ReturnsKey()
    {
        IntPtr obj = ShamirsSecretSharing.Create(3, 2);

        byte[] key = new byte[32];
        for (int i=0; i<32; i++) { key[i] = (byte)i; }
        string base64Key = Convert.ToBase64String(key);

        bool success = ShamirsSecretSharing.Split(obj, base64Key);
        Assert.True(success);

        string shard1 = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.NotNull(shard1);
        string shard2 = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.NotNull(shard2);
        string shard3 = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.NotNull(shard3);

        ShamirsSecretSharing.ClearShards(obj);

        string shard;
        shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.Null(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.Null(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.Null(shard);

        bool retval;
        retval = ShamirsSecretSharing.AddShard(obj, shard2, shard2.Length);
        Assert.True(retval);
        retval = ShamirsSecretSharing.AddShard(obj, shard1, shard1.Length);
        Assert.True(retval);

        shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.Equal(shard2, shard);
        shard = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.Equal(shard1, shard);
        shard = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.Null(shard);

        string recoveredKey = ShamirsSecretSharing.Combine(obj);
        Assert.NotNull(recoveredKey);
    }

    [Fact]
    public void Combine_WithAllShards_ReturnsKey()
    {
        IntPtr obj = ShamirsSecretSharing.Create(3, 2);

        byte[] key = new byte[32];
        for (int i=0; i<32; i++) { key[i] = (byte)i; }
        string base64Key = Convert.ToBase64String(key);

        bool success = ShamirsSecretSharing.Split(obj, base64Key);
        Assert.True(success);

        string shard;
        shard = ShamirsSecretSharing.GetShard(obj, 0);
        Assert.NotNull(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 1);
        Assert.NotNull(shard);
        shard = ShamirsSecretSharing.GetShard(obj, 2);
        Assert.NotNull(shard);

        string recoveredKey = ShamirsSecretSharing.Combine(obj);
        Assert.Equal(recoveredKey, base64Key);
    }

}
