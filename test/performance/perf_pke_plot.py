import os
import matplotlib as mpl
mpl.use('pdf')
from marshmallow import Schema, fields, post_load, ValidationError
import matplotlib.pyplot as plt
import seaborn as sns
import json
from pprint import pprint
import pandas as pd

import matplotlib.rcsetup as rcsetup
print(rcsetup.all_backends)

class PKESchema(Schema):
    ciphertext_length = fields.Integer()
    decrypt_per_sec = fields.Float()
    decrypt_us = fields.Float()
    encrypt_per_sec = fields.Float()
    encrypt_us = fields.Float()
    keygen_per_sec = fields.Float()
    keygen_us = fields.Float()
    parameter_set = fields.Integer()
    plaintext_length = fields.Integer()
    private_key_length = fields.Integer()
    public_key_length = fields.Integer()

class IBEMetricSchema(Schema):
    parameter_set = fields.String()
    master_key_length = fields.Integer()
    public_key_length = fields.Integer()
    id_length = fields.Integer()
    plaintext_length = fields.Integer()
    ciphertext_length = fields.Integer()
    keygen_us = fields.Float()
    keygen_per_sec = fields.Float()
    extract_us = fields.Float()
    extract_per_sec = fields.Float()
    encrypt_us = fields.Float()
    encrypt_per_sec = fields.Float()
    decrypt_us = fields.Float()
    decrypt_per_sec = fields.Float()

class KEXMetricSchema(Schema):
    final_per_sec = fields.Float()
    final_us = fields.Float()
    init_per_sec = fields.Float()
    init_us = fields.Float()
    parameter_set = fields.String()
    public_key_length = fields.Float()

class KEMMetricSchema(Schema):
    ciphertext_length = fields.Integer()
    decap_per_sec = fields.Integer()
    decap_us = fields.Float()
    encap_sec = fields.Integer()
    encap_us = fields.Float()
    keygen_per_sec = fields.Integer()
    keygen_us = fields.Float()
    parameter_set = fields.String()
    plaintext_length = fields.Integer()
    private_key_length = fields.Integer()
    public_key_length = fields.Integer()

class PKEMetricSchema(Schema):
    ciphertext_length = fields.Integer()
    decrypt_per_sec = fields.Integer()
    decrypt_us = fields.Float()
    encrypt_per_sec = fields.Integer()
    encrypt_us = fields.Float()
    keygen_per_sec = fields.Float()
    keygen_us = fields.Integer()
    parameter_set = fields.String()
    plaintext_length = fields.Integer()
    private_key_length = fields.Integer()
    public_key_length = fields.Integer()

class SIGMetricSchema(Schema):
    keygen_per_sec = fields.Float()
    keygen_us = fields.Integer()
    message_length = fields.Integer()
    parameter_set = fields.String()
    private_key_length = fields.Integer()
    public_key_length = fields.Integer()
    sign_per_sec = fields.Integer()
    sign_us = fields.Float()
    signature_length = fields.Integer()
    verify_per_sec = fields.Integer()
    verify_us = fields.Float()

class IBESchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(IBEMetricSchema))

class KEMSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(KEMMetricSchema))

class KeyExchangeSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(KEXMetricSchema))

class PublicKeyEncryptionSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(PKEMetricSchema))

class SignatureSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(SIGMetricSchema))

class PKCSchema(Schema):
    word_size = fields.Float()
    masking = fields.Boolean()
    ibe = fields.List(fields.Nested(IBESchema))
    kem = fields.List(fields.Nested(KEMSchema))
    kex = fields.List(fields.Nested(KeyExchangeSchema))
    pke = fields.List(fields.Nested(PublicKeyEncryptionSchema))
    sig = fields.List(fields.Nested(SignatureSchema))

class HashMetricsSchema(Schema):
    algorithm = fields.String()
    message_length = fields.Integer()
    hash_length = fields.Integer()
    hash_us = fields.Float()
    hash_per_sec = fields.Float()
    bytes_per_sec = fields.Float()

class HashAlgorithmSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(HashMetricsSchema))

class HashingSchema(Schema):
    sha2 = fields.Nested(HashAlgorithmSchema)
    sha3 = fields.Nested(HashAlgorithmSchema)

class PhantomPerformanceSchema(Schema):
    build_date = fields.String()
    compiler = fields.String()
    version = fields.String()
    timestamp = fields.String()
    pkc = fields.List(fields.Nested(PKCSchema))
    hashing = fields.Nested(HashingSchema)

# Opening JSON file
f = open('./phantom_metrics.json')

# Deserialization into object
dec_json = json.load(f)
schema = PhantomPerformanceSchema()
dec = schema.load(dec_json)

# Closing file
f.close()


class plotData:
    data = []
    def __init__(self):
        self.data = []
    def append(self, x, y, z):
        v = [x,y,z]
        self.data.append(v)

import matplotlib
print('matplotlib: {}'.format(matplotlib.__version__))

dh = plotData()
for h in dec["hashing"]["sha2"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"])
for h in dec["hashing"]["sha3"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"])
df_hash = pd.DataFrame(dh.data, columns=['Hash', 'MB/sec', 'Message length (bytes)'])

plot_hash = sns.catplot(kind="bar", x = 'Hash', y = 'MB/sec', hue='Message length (bytes)',
    data=df_hash, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=3)
ax = plot_hash.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height()):.1f}' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_hash, "upper right")
plot_hash.fig.suptitle('Hashing functions')
plt.savefig('hash.png')


dibe = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for ibe in pkc["ibe"]:
            for metrics in ibe["metrics"]:
                dibe.append(metrics["parameter_set"], metrics["extract_per_sec"], "Extract")
                dibe.append(metrics["parameter_set"], metrics["encrypt_per_sec"], "Encryption")
                dibe.append(metrics["parameter_set"], metrics["decrypt_per_sec"], "Decryption")
df_ibe = pd.DataFrame(dibe.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])

plot_ibe = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_ibe, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=2)
ax = plot_ibe.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_ibe, "upper right")
plot_ibe.fig.suptitle('IBE - DLP')
plt.savefig('ibe.png')


dkem_sabre = plotData()
dkem_kyber = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kem in pkc["kem"]:
            for metrics in kem["metrics"]:
                if kem["scheme"] == "SABRE":
                    dkem_sabre.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dkem_sabre.append(metrics["parameter_set"], metrics["encap_sec"], "Encapsulation")
                    dkem_sabre.append(metrics["parameter_set"], metrics["decap_per_sec"], "Decapsulation")
                elif kem["scheme"] == "Kyber":
                    dkem_kyber.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dkem_kyber.append(metrics["parameter_set"], metrics["encap_sec"], "Encapsulation")
                    dkem_kyber.append(metrics["parameter_set"], metrics["decap_per_sec"], "Decapsulation")

df_kem_sabre = pd.DataFrame(dkem_sabre.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])
df_kem_kyber = pd.DataFrame(dkem_kyber.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])

plot_kem_sabre = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kem_sabre, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_kem_sabre.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kem_sabre, "upper right")
plot_kem_sabre.fig.suptitle('KEM - SABRE')
plt.savefig('kem_sabre.png')

plot_kem_kyber = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kem_kyber, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_kem_kyber.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kem_kyber, "upper right")
plot_kem_kyber.fig.suptitle('KEM - Kyber')
plt.savefig('kem_kyber.png')


dkex_ecdh = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kex in pkc["kex"]:
            for metrics in kex["metrics"]:
                if kex["scheme"] == "ECDH":
                    dkex_ecdh.append(metrics["parameter_set"], metrics["init_per_sec"], "Setup")
                    dkex_ecdh.append(metrics["parameter_set"], metrics["final_per_sec"], "Shared Secret")

df_kex_ecdh = pd.DataFrame(dkex_ecdh.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])

plot_kex_ecdh = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kex_ecdh, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=5)
ax = plot_kex_ecdh.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kex_ecdh, "upper right")
plot_kex_ecdh.fig.suptitle('Key Exchange - Elliptic-curve Diffie-Hellman')
plt.savefig('kex_ecdh.png')


dpke_rsa = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for pke in pkc["pke"]:
            for metrics in pke["metrics"]:
                if pke["scheme"] == "RSAES-OAEP":
                    dpke_rsa.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dpke_rsa.append(metrics["parameter_set"], metrics["encrypt_per_sec"], "Encryption")
                    dpke_rsa.append(metrics["parameter_set"], metrics["decrypt_per_sec"], "Decryption")

df_pke_rsa = pd.DataFrame(dpke_rsa.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])

plot_pke_rsa = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_pke_rsa, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_pke_rsa.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_pke_rsa, "upper right")
plot_pke_rsa.fig.suptitle('Public Key Encryption - RSAES-OAEP')
plt.savefig('pke_rsa.png')


dsig_dilithium = plotData()
dsig_falcon = plotData()
dsig_ecdsa = plotData()
dsig_eddsa = plotData()
dsig_rsa = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for sig in pkc["sig"]:
            for metrics in sig["metrics"]:
                if sig["scheme"] == "RSASSA-PSS":
                    dsig_rsa.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dsig_rsa.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign")
                    dsig_rsa.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify")
                elif sig["scheme"] == "Dilithium":
                    dsig_dilithium.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dsig_dilithium.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign")
                    dsig_dilithium.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify")
                elif sig["scheme"] == "Falcon":
                    dsig_falcon.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dsig_falcon.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign")
                    dsig_falcon.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify")
                elif sig["scheme"] == "ECDSA":
                    dsig_ecdsa.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dsig_ecdsa.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign")
                    dsig_ecdsa.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify")
                elif sig["scheme"] == "EDDSA":
                    dsig_eddsa.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation")
                    dsig_eddsa.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign")
                    dsig_eddsa.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify")

df_sig_dilithium = pd.DataFrame(dsig_dilithium.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])
df_sig_falcon = pd.DataFrame(dsig_falcon.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])
df_sig_ecdsa = pd.DataFrame(dsig_ecdsa.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])
df_sig_eddsa = pd.DataFrame(dsig_eddsa.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])
df_sig_rsa = pd.DataFrame(dsig_rsa.data, columns=['Parameter Set', 'Operations/sec', 'Operation'])

plot_sig_dilithium = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_sig_dilithium, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_sig_dilithium.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_dilithium, "upper right")
plot_sig_dilithium.fig.suptitle('Digital Signature - Dilithium')
plt.savefig('sig_dilithium.png')

plot_sig_falcon = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_sig_falcon, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_sig_falcon.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_falcon, "upper right")
plot_sig_falcon.fig.suptitle('Digital Signature - Falcon')
plt.savefig('sig_falcon.png')

plot_sig_ecdsa = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_sig_ecdsa, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_sig_ecdsa.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_ecdsa, "upper right")
plot_sig_ecdsa.fig.suptitle('Digital Signature - ECDSA')
plt.savefig('sig_ecdsa.png')

plot_sig_eddsa = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_sig_eddsa, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_sig_eddsa.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_eddsa, "upper right")
plot_sig_eddsa.fig.suptitle('Digital Signature - EDDSA')
plt.savefig('sig_eddsa.png')

plot_sig_rsa = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_sig_rsa, palette=['purple', 'steelblue', 'orange'], legend_out=False, height=5, aspect=1.5)
ax = plot_sig_rsa.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_rsa, "upper right")
plot_sig_rsa.fig.suptitle('Digital Signature - RSASSA-PSS')
plt.savefig('sig_rsa.png')

# Plot bytes per second for each algorithm with message lengths of 16, 512 and 16384 bytes

