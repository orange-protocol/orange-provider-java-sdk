package io.ont.entity;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Helper;
import com.github.ontio.sdk.exception.SDKException;
import com.github.ontio.sdk.manager.ECIES;
import com.github.ontio.sdk.wallet.Wallet;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;

@Slf4j
public class OrangeProviderOntSdk {
    Account account;
    OntSdk ontSdk;
    public static OrangeProviderOntSdk instance = null;

    public static synchronized OrangeProviderOntSdk getOrangeProviderOntSdk(String network, String walletPath, String password) {
        instance = new OrangeProviderOntSdk(network, walletPath, password);
        return instance;
    }

    public OrangeProviderOntSdk() {
    }

    public OrangeProviderOntSdk(String network, String walletPath, String password) {
        OntSdk ontSdk = OntSdk.getInstance();
        String url = "http://polaris2.ont.io:20336";
        if (network.equalsIgnoreCase("MAINNET")) {
            url = "http://dappnode2.ont.io:20336";
        }
        ontSdk.setRpc(url);
        ontSdk.openWalletFile(walletPath);
        Wallet wallet = ontSdk.getWalletMgr().getWallet();
        String defaultAccountAddress = wallet.getDefaultAccountAddress();
        Account account = null;
        try {
            account = ontSdk.getWalletMgr().getAccount(defaultAccountAddress, password);
        } catch (Exception e) {
            log.error("password error or wallet error");
            e.printStackTrace();
        }
        this.account = account;
        this.ontSdk = ontSdk;

    }

    public byte[] signData(byte[] data) throws SDKException {
        OntSdk ontSdk = instance.getOntSdk();
        byte[] sig = ontSdk.signatureData(instance.getAccount(), data);
        return sig;
    }


    public String getSelfDID() {
        Account account = instance.getAccount();
        String address = account.getAddressU160().toBase58();
        return "did:ont:" + address;
    }

    public byte[] getDIDPubkey(String did) {
        OntSdk ontSdk = instance.getOntSdk();
        String publicKeyJSON = null;
        try {
            publicKeyJSON = ontSdk.nativevm().ontId().sendGetPublicKeys(did);
        } catch (Exception e) {
            log.error("did has not registered");
            e.printStackTrace();
        }
        JSONArray jsonArray = JSON.parseArray(publicKeyJSON);
        JSONObject jsonObject = (JSONObject) jsonArray.get(0);
        String publicKeyHex = jsonObject.get("publicKeyHex").toString();
        return Helper.hexToBytes(publicKeyHex);
    }

    public byte[] encryptDataWithDID(byte[] data, String did) {
        byte[] didPubkey = getDIDPubkey(did);
        // encrypt
        ECIES.setDigest(new SHA256Digest());
        String[] ret = new String[0];
        try {
            ret = ECIES.Encrypt(Helper.toHexString(didPubkey), data);
        } catch (Exception e) {
            log.error(" encrypt data error ");
            e.printStackTrace();
        }
        StringBuilder sb = new StringBuilder();
        for (String str : ret) {
            sb.append(str);
        }
        String enhex = sb.toString();
        System.out.println(enhex);
        return Helper.hexToBytes(enhex);
    }


    public byte[] decryptData(byte[] msg) {
        String encrypted = Helper.toHexString(msg);
        String substring1 = encrypted.substring(0, 32);
        String substring2 = encrypted.substring(32, 162);
        String substring3 = encrypted.substring(162);
        String[] ret = new String[]{substring1, substring2, substring3};
        byte[] decryptedbts = new byte[0];
        try {
            decryptedbts = ECIES.Decrypt(Helper.toHexString(account.serializePrivateKey()), ret);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedbts;
    }


    public Boolean verifySig(String did, byte[] msg, byte[] sigBytes) {
        byte[] didPubkey = getDIDPubkey(did);
        OntSdk ontSdk = instance.getOntSdk();
        boolean res = false;
        try {
            res = ontSdk.verifySignature(didPubkey, msg, sigBytes);
        } catch (SDKException e) {
            log.error("vertify Signature error ");
            e.printStackTrace();
        }
        return res;
    }


    public Account getAccount() {
        return account;
    }

    public OntSdk getOntSdk() {
        return ontSdk;
    }


}
