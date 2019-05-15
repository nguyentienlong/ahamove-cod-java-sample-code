package com.ahamove.cod;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
// Bouncy castle imports
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;


public class PGPHelper {

    private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2(one shifted bitwise 16 places)
    private static final Map<String, PGPHelper> MAP = new ConcurrentHashMap<>();
    private static final String DEFAULT_SERVICE_CODE = "ONE_SERVICE";

    private PGPPublicKey encryptionPublicKey;
    private PGPPublicKey signaturePublicKey;
    private PGPSecretKeyRingCollection pgpSec;
    private PGPSecretKey secretKey;
    private PGPSignatureGenerator signatureGenerator;
    private char[] password;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private PGPHelper(byte[] publicKey, byte[] privateKey, String password
    ) throws Exception {
        this.password = password.toCharArray();
        InputStream pubStream = new ByteArrayInputStream(publicKey);
        InputStream priStream = new ByteArrayInputStream(privateKey);
        readKey(pubStream, null, null, priStream);

    }

    private PGPHelper(String publicKeyPath, String privateKeyPath, String password,
            Long encryptpublicKeyId,
            Long signaturePublicKeyId) throws Exception, FileNotFoundException {

        InputStream pubStream = new FileInputStream(new File(publicKeyPath));
        InputStream priStream = new FileInputStream(new File(privateKeyPath));
        this.password = password.toCharArray();
        readKey(pubStream, encryptpublicKeyId, signaturePublicKeyId, priStream);
    }

    private void readKey(InputStream pubStream, Long encryptpublicKeyId, Long signaturePublicKeyId, InputStream priStream) throws Exception {
        try {
            readPublicKey(pubStream, encryptpublicKeyId, signaturePublicKeyId);
            this.pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(priStream));
            this.secretKey = readSecretKey(pgpSec);

        }
        catch (IOException | PGPException | NoSuchProviderException ex) {
            throw new Exception(ex.getMessage(), ex);
        }
        finally {
            try {
                pubStream.close();
                priStream.close();
            }
            catch (IOException ex) {
                // NOOP
            }
        }
    }

    public static void init(String privateKeyPath, String publicKeyPath, String password) throws Exception, FileNotFoundException {
        init(DEFAULT_SERVICE_CODE, privateKeyPath, publicKeyPath, password, null, null);
    }

    public static void init(String privateKeyPath, String publicKeyPath, String password, Long encryptionPublicKeyId, Long verifyPublicKeyId) throws Exception, FileNotFoundException {
        init(DEFAULT_SERVICE_CODE, privateKeyPath, publicKeyPath, password, encryptionPublicKeyId, verifyPublicKeyId);
    }

    public static void init(String serviceCode, String privateKeyPath, String publicKeyPath, String password) throws Exception, FileNotFoundException {
        init(serviceCode, privateKeyPath, publicKeyPath, password, null, null);
    }

    public static void init(String serviceCode, byte[] privateKey, byte[] publicKey, String password) throws Exception, FileNotFoundException {
        MAP.put(serviceCode, new PGPHelper(publicKey, privateKey, password));
    }

    public static void init(String serviceCode, String privateKeyPath, String publicKeyPath, String password, Long encryptionPublicKeyId, Long verifyPublicKeyId) throws Exception, FileNotFoundException {
        MAP.put(serviceCode, new PGPHelper(publicKeyPath, privateKeyPath, password, encryptionPublicKeyId, verifyPublicKeyId));
    }

    public static PGPHelper getInstance() {
        return MAP.get(DEFAULT_SERVICE_CODE);
    }

    public static PGPHelper getInstance(String serviceCode) {
        return MAP.get(serviceCode);
    }

    public void decryptAndVerifySignature(byte[] encryptData, OutputStream decryptData) throws Exception {
        try {
            InputStream bais = new ByteArrayInputStream(encryptData);
            bais = PGPUtil.getDecoderStream(bais);
            PGPObjectFactory objectFactory = new PGPObjectFactory(bais);
            Object firstObject = objectFactory.nextObject();
            PGPEncryptedDataList dataList = (PGPEncryptedDataList) (firstObject instanceof PGPEncryptedDataList ? firstObject : objectFactory.nextObject());
            Iterator it = dataList.getEncryptedDataObjects();
            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData encryptedData = null;
            while (privateKey == null && it.hasNext()) {
                encryptedData = (PGPPublicKeyEncryptedData) it.next();
                privateKey = findSecretKey(encryptedData.getKeyID());
            }
            if (encryptedData == null || privateKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            InputStream clear = encryptedData.getDataStream(privateKey, "BC");
            PGPObjectFactory clearObjectFactory = new PGPObjectFactory(clear);
            Object message = clearObjectFactory.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                objectFactory = new PGPObjectFactory(cData.getDataStream());
                message = objectFactory.nextObject();
            }

            PGPOnePassSignature calculatedSignature = null;
            if (message instanceof PGPOnePassSignatureList) {
                calculatedSignature = ((PGPOnePassSignatureList) message).get(0);
                calculatedSignature.initVerify(signaturePublicKey, "BC");
                message = objectFactory.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream literalDataStream = ld.getInputStream();
                int ch;
                while ((ch = literalDataStream.read()) >= 0) {
                    if (calculatedSignature != null) {
                        calculatedSignature.update((byte) ch);
                    }
                    decryptData.write((byte) ch);
                }
            }
            else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (calculatedSignature != null) {
                PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
                PGPSignature messageSignature = (PGPSignature) signatureList.get(0);
                if (!calculatedSignature.verify(messageSignature)) {
                    throw new PGPException("signature verification failed");
                }
            }

            if (encryptedData.isIntegrityProtected()) {
                if (!encryptedData.verify()) {
                    throw new PGPException("message failed integrity check");
                }
            }
        }
        catch (IOException | IllegalArgumentException | NoSuchProviderException | PGPException | SignatureException ex) {
            throw new Exception(ex.getMessage(), ex);
        }
    }

    public String decrypt(byte[] encryptData) throws Exception {
        InputStream bais = new ByteArrayInputStream(encryptData);
        bais = PGPUtil.getDecoderStream(bais);
        PGPObjectFactory pgpF = new PGPObjectFactory(bais);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        }
        else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedData = null;
        while (privateKey == null && it.hasNext()) {
            encryptedData = (PGPPublicKeyEncryptedData) it.next();
            privateKey = findSecretKey(encryptedData.getKeyID());
        }
        if (privateKey == null || encryptedData == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }
        InputStream clear = encryptedData.getDataStream(privateKey, "BC");
        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
        Object message = plainFact.nextObject();
        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
            message = pgpFact.nextObject();
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                baos.write(ch);
            }
        }
        else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("encrypted message contains a signed message - not literal data.");
        }
        else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }
        return new String(baos.toByteArray());
    }

    public byte[] encrypt(byte[] data) throws IOException, NoSuchProviderException, PGPException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(data, baos);
        return baos.toByteArray();

    }

    private void readPublicKey(InputStream in, Long publicKeyId, Long signaturePublicKeyId) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pkCol = new PGPPublicKeyRingCollection(in);
        PGPPublicKeyRing pkRing;
        Iterator it = pkCol.getKeyRings();
        if (publicKeyId == null || publicKeyId == -1) {
            while (it.hasNext()) {
                pkRing = (PGPPublicKeyRing) it.next();
                Iterator pkIt = pkRing.getPublicKeys();
                while (pkIt.hasNext()) {
                    PGPPublicKey key = (PGPPublicKey) pkIt.next();
                    if (key.isEncryptionKey()) {
                        encryptionPublicKey = key;
                        break;
                    }
                }
            }

        }
        else {
            encryptionPublicKey = pkCol.getPublicKey(publicKeyId);
        }
        if (encryptionPublicKey == null) {
            throw new PGPException("Invalid public Key");
        }
        if (signaturePublicKeyId == null || signaturePublicKeyId == -1) {
            signaturePublicKey = encryptionPublicKey;
        }
        else {
            signaturePublicKey = pkCol.getPublicKey(signaturePublicKeyId);
        }
    }

    public void encryptAndSign(byte[] data, OutputStream out) throws Exception {
        try {
            out = new ArmoredOutputStream(out);
            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(PGPEncryptedDataGenerator.CAST5, new SecureRandom(), "BC");
            encryptedDataGenerator.addMethod(encryptionPublicKey);
            PGPCompressedDataGenerator comData = null;
            try (OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE])) {
                comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
                try (OutputStream compressedOut = comData.open(encryptedOut)) {
                    PGPSignatureGenerator pgpsg = createSignatureGenerator();
                    pgpsg.generateOnePassVersion(false).encode(compressedOut);
                    writeToLiteralData(pgpsg, compressedOut, data);
                    pgpsg.generate().encode(compressedOut);
                }
            }

            finally {
                if (comData != null) {
                    try {
                        comData.close();
                    }
                    catch (IOException ex) {
                        //NO OP
                    }
                }
                try {
                    encryptedDataGenerator.close();
                }
                catch (IOException ex) {
                    //NO OP
                }
                out.close();
            }
        }
        catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | PGPException | SignatureException ex) {
            throw new Exception(ex.getMessage(), ex);
        }
    }

    private PGPSignatureGenerator createSignatureGenerator() throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        if (signatureGenerator == null) {
            PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(password, "BC");
            PGPPublicKey internalPublicKey = secretKey.getPublicKey();
            PGPSignatureGenerator generator = new PGPSignatureGenerator(internalPublicKey.getAlgorithm(), HashAlgorithmTags.SHA1, "BC");
            generator.initSign(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
            for (Iterator i = internalPublicKey.getUserIDs(); i.hasNext();) {
                String userId = (String) i.next();
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, userId);
                generator.setHashedSubpackets(spGen.generate());
                break;
            }
            this.signatureGenerator = generator;
        }
        return signatureGenerator;
    }

    private void encrypt(byte[] data, OutputStream out) throws IOException, NoSuchProviderException, PGPException {
        out = new DataOutputStream(out);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = null;
        try {
            comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
            writeToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, data);
        }
        finally {
            if (comData != null) {
                comData.close();
            }
        }
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedDataGenerator.CAST5, new SecureRandom(), "BC");
        cPk.addMethod(encryptionPublicKey);
        byte[] bytes = bOut.toByteArray();
        try (OutputStream cOut = cPk.open(out, bytes.length)) {
            cOut.write(bytes);
        }

    }

    private PGPPrivateKey findSecretKey(long keyID) throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        return pgpSecKey.extractPrivateKey(password, "BC");
    }

    private static void writeToLiteralData(OutputStream out, char fileType, byte[] data) throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, "temp", data.length, new Date());
        pOut.write(data);
    }

    private static void writeToLiteralData(PGPSignatureGenerator signatureGenerator, OutputStream out, byte[] data) throws IOException, SignatureException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayInputStream contentStream = new ByteArrayInputStream(data);
        try (OutputStream literalOut = lData.open(out, PGPLiteralData.BINARY, "pgp", new Date(), new byte[BUFFER_SIZE])) {
            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = contentStream.read(buf, 0, buf.length)) > 0) {
                literalOut.write(buf, 0, len);
                signatureGenerator.update(buf, 0, len);
            }
        }
        finally {
            lData.close();
        }
    }

    private PGPSecretKey readSecretKey(PGPSecretKeyRingCollection collection) throws IOException, PGPException, NoSuchProviderException {
        Iterator it = collection.getKeyRings();
        PGPSecretKeyRing pbr;
        while (it.hasNext()) {
            Object readData = it.next();
            if (readData instanceof PGPSecretKeyRing) {
                pbr = (PGPSecretKeyRing) readData;
                return pbr.getSecretKey();
            }
        }
        throw new IllegalArgumentException("secret key for message not found.");
    }
}
