import os
import matplotlib as mpl
mpl.use('pdf')
from marshmallow import Schema, fields, post_load, ValidationError
import matplotlib.pyplot as plt
import seaborn as sns
import json
from pprint import pprint
import pandas as pd

#import matplotlib.rcsetup as rcsetup
#print(rcsetup.all_backends)

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

class XOFMetricsSchema(Schema):
    algorithm = fields.String()
    message_length = fields.Integer()
    xof_length = fields.Integer()
    xof_us = fields.Float()
    xof_per_sec = fields.Float()
    bytes_per_sec = fields.Float()

class HashAlgorithmSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(HashMetricsSchema))

class XOFAlgorithmSchema(Schema):
    scheme = fields.String()
    metrics = fields.List(fields.Nested(XOFMetricsSchema))

class HashingSchema(Schema):
    sha2 = fields.Nested(HashAlgorithmSchema)
    sha3 = fields.Nested(HashAlgorithmSchema)

class XOFSchema(Schema):
    shake = fields.Nested(XOFAlgorithmSchema)

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
    xof = fields.Nested(XOFSchema)
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


sns.set_style("darkgrid")

dh = plotData()
for h in dec["hashing"]["sha2"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"], "SHA-2")
for h in dec["hashing"]["sha3"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"], "SHA-3")
for h in dec["xof"]["shake"]["metrics"]:
    dh.append(h["algorithm"], h["bytes_per_sec"] / (1024.0*1024.0), h["message_length"], "SHAKE")
df_hash = pd.DataFrame(dh.data, columns=['Hash', 'MB/sec', 'Message length (bytes)', 'Algorithm'])

plot_hash = sns.catplot(kind="bar", x = 'Hash', y = 'MB/sec', col = 'Algorithm', hue='Message length (bytes)',
    data=df_hash, legend_out=False, height=5, aspect=2, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 3))
for ax in plot_hash.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
    
sns.move_legend(plot_hash, "upper left", bbox_to_anchor=(.1, 0.95))
plot_hash.set_titles("{col_name}", size=20)
plot_hash.set(xlabel="")
plt.subplots_adjust(hspace = 0.2)
plt.savefig('hash.png', bbox_inches="tight")


dsymkey_aes = plotData()
for enc in dec["symmetric_key"]["encryption"]:
    if enc["scheme"] == "AES-ECB":
        for v in enc["metrics"]:
            dsymkey_aes.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes = pd.DataFrame(dsymkey_aes.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes, legend_out=False, height=8, aspect=3, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 11))
for ax in plot_symkey_aes.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes, "upper right", bbox_to_anchor=(.95, 0.75))
plot_symkey_aes.set_titles("{col_name}", size=24)
plot_symkey_aes.set(xlabel="Key length (bytes)")
plt.subplots_adjust(hspace = 0.15)
plt.savefig('aes_ecb.png')


dsymkey_aes_ctr = plotData()
for enc in dec["symmetric_key"]["encryption"]:
    if enc["scheme"] == "AES-CTR":
        for v in enc["metrics"]:
            dsymkey_aes_ctr.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes_ctr.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes_ctr = pd.DataFrame(dsymkey_aes_ctr.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes_ctr = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes_ctr, legend_out=False, height=8, aspect=3, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 11))
for ax in plot_symkey_aes_ctr.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes_ctr, "upper right", bbox_to_anchor=(.95, 0.75))
plot_symkey_aes_ctr.set_titles("{col_name}", size=24)
plot_symkey_aes_ctr.set(xlabel="Key length (bytes)")
plt.subplots_adjust(hspace = 0.15)
plt.savefig('aes_ctr.png')


dsymkey_aes_gcm = plotData()
for enc in dec["symmetric_key"]["auth_encryption"]:
    if enc["scheme"] == "AES-GCM":
        for v in enc["metrics"]:
            dsymkey_aes_gcm.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes_gcm.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes_gcm = pd.DataFrame(dsymkey_aes_gcm.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes_gcm = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes_gcm, legend_out=False, height=8, aspect=3, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 11))
for ax in plot_symkey_aes_gcm.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes_gcm, "upper right", bbox_to_anchor=(.95, 0.75))
plot_symkey_aes_gcm.set_titles("{col_name}", size=24)
plot_symkey_aes_gcm.set(xlabel="Key length (bytes)")
plt.subplots_adjust(hspace = 0.15)
plt.savefig('aes_gcm.png')


dsymkey_aes_ccm = plotData()
for enc in dec["symmetric_key"]["auth_encryption"]:
    if enc["scheme"] == "AES-CCM":
        for v in enc["metrics"]:
            dsymkey_aes_ccm.append(enc["key_length"], v["encrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Encryption")
            dsymkey_aes_ccm.append(enc["key_length"], v["decrypt_bytes_per_sec"] / (1024.0*1024.0), v["message_length"], "Decryption")
df_symkey_aes_ccm = pd.DataFrame(dsymkey_aes_ccm.data, columns=['Key length (bytes)', 'MB/sec', 'Message length (bytes)', 'Operation'])

plot_symkey_aes_ccm = sns.catplot(kind="bar", x = 'Key length (bytes)', y = 'MB/sec', col = "Operation", hue='Message length (bytes)',
    data=df_symkey_aes_ccm, legend_out=False, height=8, aspect=3, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 11))
for ax in plot_symkey_aes_ccm.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_symkey_aes_ccm, "upper right", bbox_to_anchor=(.95, 0.75))
plot_symkey_aes_ccm.set_titles("{col_name}", size=24)
plot_symkey_aes_ccm.set(xlabel="Key length (bytes)")
plt.subplots_adjust(hspace = 0.15)
plt.savefig('aes_ccm.png')


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
    data=df_ibe, legend_out=False, height=5, aspect=2, palette=sns.color_palette("GnBu_d", 3))
ax = plot_ibe.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_ibe, "upper right")
plt.savefig('ibe.png')


dkem = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kem in pkc["kem"]:
            for metrics in kem["metrics"]:
                dkem.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", kem["scheme"])
                dkem.append(metrics["parameter_set"], metrics["encap_sec"], "Encapsulation", kem["scheme"])
                dkem.append(metrics["parameter_set"], metrics["decap_per_sec"], "Decapsulation", kem["scheme"])

df_kem = pd.DataFrame(dkem.data, columns=['Parameter Set', 'Operations/sec', 'Operation', 'Scheme'])

plot_kem = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', col = 'Scheme', hue='Operation',
    data=df_kem, legend_out=False, height=5, aspect=1.5, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 3))
for ax in plot_kem.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height()):.1f}' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kem, "upper right", bbox_to_anchor=(.95, 0.95))
plot_kem.set_titles("{col_name}", size=20)
plot_kem.set(xlabel="Parameter Set")
plt.subplots_adjust(hspace = 0.25)
plt.savefig('kem.png')


dkex = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for kex in pkc["kex"]:
            for metrics in kex["metrics"]:
                if kex["scheme"] == "ECDH":
                    dkex.append(metrics["parameter_set"], metrics["init_per_sec"], "Setup", kex["scheme"])
                    dkex.append(metrics["parameter_set"], metrics["final_per_sec"], "Shared Secret", kex["scheme"])

df_kex = pd.DataFrame(dkex.data, columns=['Parameter Set', 'Operations/sec', 'Operation', 'Scheme'])

plot_kex = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', col = 'Scheme', hue='Operation',
    data=df_kex, legend_out=False, height=5, aspect=5, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 3))
ax = plot_kex.facet_axis(0, 0)
for c in ax.containers:
    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
    ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_kex, "upper right")
plot_kex.set_titles("{col_name}", size=20)
plot_kex.set(xlabel="Parameter Set")
plt.subplots_adjust(hspace = 0.25)
plt.savefig('kex.png')


#dpke = plotData()
#for pkc in dec["pkc"]:
#    if pkc["masking"] == True:
#        for pke in pkc["pke"]:
#            for metrics in pke["metrics"]:
#                if pke["scheme"] == "RSAES-OAEP":
#                    dpke.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", pke["scheme"])
#                    dpke.append(metrics["parameter_set"], metrics["encrypt_per_sec"], "Encryption", pke["scheme"])
#                    dpke.append(metrics["parameter_set"], metrics["decrypt_per_sec"], "Decryption", pke["scheme"])
#
#df_pke = pd.DataFrame(dpke.data, columns=['Parameter Set', 'Operations/sec', 'Operation', 'Scheme'])
#
#plot_pke = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', col = 'Scheme', hue='Operation',
#    data=df_pke, legend_out=False, height=5, aspect=1.5, col_wrap=1, sharex=False, palette=sns.color_palette("GnBu_d", 3))
#ax = plot_pke.facet_axis(0, 0)
#for c in ax.containers:
#    labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
#    ax.bar_label(c, labels=labels, label_type='edge')
#sns.move_legend(plot_pke, "upper right")
#plot_pke.set_titles("{col_name}", size=20)
#plot_pke.set(xlabel="Parameter Set")
#plt.subplots_adjust(hspace = 0.25)
#plt.savefig('pke.png')


dsig = plotData()
for pkc in dec["pkc"]:
    if pkc["masking"] == True:
        for sig in pkc["sig"]:
            for metrics in sig["metrics"]:
                dsig.append(metrics["parameter_set"], metrics["keygen_per_sec"], "Key Generation", sig["scheme"])
                dsig.append(metrics["parameter_set"], metrics["sign_per_sec"], "Sign", sig["scheme"])
                dsig.append(metrics["parameter_set"], metrics["verify_per_sec"], "Verify", sig["scheme"])

df_sig = pd.DataFrame(dsig.data, columns=['Parameter Set', 'Operations/sec', 'Operation', 'Scheme'])
plot_sig = sns.catplot(kind="bar", x = 'Parameter Set', y = 'Operations/sec', col = 'Scheme', hue='Operation',
    data=df_sig, legend_out=False, height=5, aspect=1.5, col_wrap=3, sharex=False, sharey=False, palette=sns.color_palette("GnBu_d", 3))
for ax in plot_sig.axes.ravel():
    for c in ax.containers:
        labels = [f'{(v.get_height() / 1000):.1f}K' for v in c]
        ax.bar_label(c, labels=labels, label_type='edge')
sns.move_legend(plot_sig, "upper right", bbox_to_anchor=(.85, 0.35))
plot_sig.set_titles("{col_name}", size=20)
plot_sig.set(xlabel="Parameter Set")
plt.subplots_adjust(hspace = 0.25)
plt.savefig('sig.png')


# Plot bytes per second for each algorithm with message lengths of 16, 512 and 16384 bytes

