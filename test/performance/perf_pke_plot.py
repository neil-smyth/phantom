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

class SymKeyEncMetricsSchema(Schema):
    decrypt_bytes_per_sec = fields.Integer()
    encrypt_bytes_per_sec = fields.Integer()
    keygen_per_sec = fields.Float()
    message_length = fields.Integer()


class SymKeyEncSchema(Schema):
    key_length = fields.Integer()
    scheme = fields.String()
    metrics = fields.List(fields.Nested(SymKeyEncMetricsSchema))

class SymmetricKeySchema(Schema):
    encryption = fields.List(fields.Nested(SymKeyEncSchema))
    auth_encryption = fields.List(fields.Nested(SymKeyEncSchema))

class PhantomPerformanceSchema(Schema):
    build_date = fields.String()
    compiler = fields.String()
    version = fields.String()
    timestamp = fields.String()
    pkc = fields.List(fields.Nested(PKCSchema))
    hashing = fields.Nested(HashingSchema)
    symmetric_key = fields.Nested(SymmetricKeySchema)

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
    def append(self, w, x, y, z):
        v = [w,x,y,z]
        self.data.append(v)


sns.set_palette("RdPu", 3)

dh = plotData()
for h in dec["hashing"]["sha2"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"], None)
for h in dec["hashing"]["sha3"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"], None)
df_hash = pd.DataFrame(dh.data, columns=['Hash', 'MB/sec', 'Message length (bytes)', None])

plot_hash = sns.catplot(kind="bar", x = 'Hash', y = 'MB/sec', hue='Message length (bytes)',
    data=df_hash, legend_out=False, height=5, aspect=3)
ax = plot_hash.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height()):.1f}' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_hash, "upper right")
plot_hash.fig.suptitle('Hashing functions')
plt.savefig('hash.png')


sns.set_palette("RdPu", 11)

dsymkey_aes = plotData()
for enc in dec["symmetric_key"]["encryption"]:
    if enc["scheme"] == "AES-ECB":
        for v in enc["metrics"]:
            dsymkey_aes.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes = pd.DataFrame(dsymkey_aes.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes, legend_out=False, height=8, aspect=3, col_wrap=1)
for ax in plot_symkey_aes.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes, "upper right")
plot_symkey_aes.fig.suptitle('Symmetric Key - Encryption - AES-ECB')
plt.savefig('aes_ecb.png')


dsymkey_aes_ctr = plotData()
for enc in dec["symmetric_key"]["encryption"]:
    if enc["scheme"] == "AES-CTR":
        for v in enc["metrics"]:
            dsymkey_aes_ctr.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes_ctr.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes_ctr = pd.DataFrame(dsymkey_aes_ctr.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes_ctr = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes_ctr, legend_out=False, height=8, aspect=3, col_wrap=1)
for ax in plot_symkey_aes_ctr.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes_ctr, "upper right")
plot_symkey_aes_ctr.fig.suptitle('Symmetric Key - Encryption - AES-ECB')
plt.savefig('aes_ctr.png')


dsymkey_aes_gcm = plotData()
for enc in dec["symmetric_key"]["auth_encryption"]:
    if enc["scheme"] == "AES-GCM":
        for v in enc["metrics"]:
            dsymkey_aes_gcm.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes_gcm.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes_gcm = pd.DataFrame(dsymkey_aes_gcm.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes_gcm = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes_gcm, legend_out=False, height=8, aspect=3, col_wrap=1)
for ax in plot_symkey_aes_gcm.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes_gcm, "upper right")
plot_symkey_aes_gcm.fig.suptitle('Symmetric Key - Authenticated Encryption - AES-GCM')
plt.savefig('aes_gcm.png')


sns.set_palette("RdPu", 3)

dibe = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for ibe in pkc["ibe"]:
            for metrics in ibe["metrics"]:
                dibe.append(metrics["parameter_set"], metrics["extract_per_sec"], "Extract", None)
                dibe.append(metrics["parameter_set"], metrics["encrypt_per_sec"], "Encryption", None)
                dibe.append(metrics["parameter_set"], metrics["decrypt_per_sec"], "Decryption", None)
df_ibe = pd.DataFrame(dibe.data, columns=['Parameter Set', 'Operations/sec', 'Operation', None])

plot_ibe = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_ibe, legend_out=False, height=5, aspect=2)
ax = plot_ibe.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_ibe, "upper right")
plot_ibe.fig.suptitle('IBE - DLP')
plt.savefig('ibe.png')


sns.set_palette("RdPu", 3)

dkem_sabre = plotData()
dkem_kyber = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kem in pkc["kem"]:
            for metrics in kem["metrics"]:
                if kem["scheme"] == "SABRE":
                    dkem_sabre.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", None)
                    dkem_sabre.append(metrics["parameter_set"], metrics["encap_sec"], "Encapsulation", None)
                    dkem_sabre.append(metrics["parameter_set"], metrics["decap_per_sec"], "Decapsulation", None)
                elif kem["scheme"] == "Kyber":
                    dkem_kyber.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", None)
                    dkem_kyber.append(metrics["parameter_set"], metrics["encap_sec"], "Encapsulation", None)
                    dkem_kyber.append(metrics["parameter_set"], metrics["decap_per_sec"], "Decapsulation", None)

df_kem_sabre = pd.DataFrame(dkem_sabre.data, columns=['Parameter Set', 'Operations/sec', 'Operation', None])
df_kem_kyber = pd.DataFrame(dkem_kyber.data, columns=['Parameter Set', 'Operations/sec', 'Operation', None])

plot_kem_sabre = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kem_sabre, legend_out=False, height=5, aspect=1.5)
ax = plot_kem_sabre.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kem_sabre, "upper right")
plot_kem_sabre.fig.suptitle('KEM - SABRE')
plt.savefig('kem_sabre.png')

plot_kem_kyber = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kem_kyber, legend_out=False, height=5, aspect=1.5)
ax = plot_kem_kyber.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kem_kyber, "upper right")
plot_kem_kyber.fig.suptitle('KEM - Kyber')
plt.savefig('kem_kyber.png')


sns.set_palette("RdPu", 2)

dkex_ecdh = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kex in pkc["kex"]:
            for metrics in kex["metrics"]:
                if kex["scheme"] == "ECDH":
                    dkex_ecdh.append(metrics["parameter_set"], metrics["init_per_sec"], "Setup", None)
                    dkex_ecdh.append(metrics["parameter_set"], metrics["final_per_sec"], "Shared Secret", None)

df_kex_ecdh = pd.DataFrame(dkex_ecdh.data, columns=['Parameter Set', 'Operations/sec', 'Operation', None])

plot_kex_ecdh = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_kex_ecdh, legend_out=False, height=5, aspect=5)
ax = plot_kex_ecdh.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kex_ecdh, "upper right")
plot_kex_ecdh.fig.suptitle('Key Exchange - Elliptic-curve Diffie-Hellman')
plt.savefig('kex_ecdh.png')


sns.set_palette("RdPu", 3)

dpke_rsa = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for pke in pkc["pke"]:
            for metrics in pke["metrics"]:
                if pke["scheme"] == "RSAES-OAEP":
                    dpke_rsa.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", None)
                    dpke_rsa.append(metrics["parameter_set"], metrics["encrypt_per_sec"], "Encryption", None)
                    dpke_rsa.append(metrics["parameter_set"], metrics["decrypt_per_sec"], "Decryption", None)

df_pke_rsa = pd.DataFrame(dpke_rsa.data, columns=['Parameter Set', 'Operations/sec', 'Operation', None])

plot_pke_rsa = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', hue='Operation',
    data=df_pke_rsa, legend_out=False, height=5, aspect=1.5)
ax = plot_pke_rsa.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_pke_rsa, "upper right")
plot_pke_rsa.fig.suptitle('Public Key Encryption - RSAES-OAEP')
plt.savefig('pke_rsa.png')


sns.set_palette("RdPu", 3)
dsig = plotData()
dsig_keygen = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for sig in pkc["sig"]:
            for metrics in sig["metrics"]:
                dsig.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign", sig["scheme"])
                dsig.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify", sig["scheme"])
                dsig_keygen.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", sig["scheme"])

df_sig = pd.DataFrame(dsig.data, columns=['Parameter Set', 'Operations/sec', 'Operation', 'Scheme'])
plot_sig = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', col = 'Scheme', hue='Operation',
    data=df_sig, legend_out=False, height=5, aspect=1.5, col_wrap=1, sharex=False, sharey=False)
for ax in plot_sig.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig, "upper right")
plot_sig.fig.suptitle('Digital Signature')
plt.savefig('sig.png')

df_sig_keygen = pd.DataFrame(dsig_keygen.data, columns=['Parameter Set', 'KeyGen/sec', 'Operation', 'Scheme'])
plot_sig_keygen = sns.catplot(kind="bar", x = 'Parameter Set', y = 'KeyGen/sec', col='Scheme', hue='Operation',
    data=df_sig_keygen, legend_out=False, height=5, aspect=1.5, col_wrap=1, sharex=False, sharey=False)
for ax in plot_sig_keygen.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig_keygen, "upper right")
plot_sig_keygen.fig.suptitle('Digital Signature')
plt.savefig('sig_keygen.png')


# Plot bytes per second for each algorithm with message lengths of 16, 512 and 16384 bytes

