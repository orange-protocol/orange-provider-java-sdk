package io.ont.orangeproviderjavasdk;


import io.ont.entity.OrangeProviderOntSdk;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

//@SpringBootTest
class OrangeProviderJavaSdkApplicationTests {


    @Test
    public void tets2() throws Exception {
        OrangeProviderOntSdk orangeProviderOntSdk = OrangeProviderOntSdk.getOrangeProviderOntSdk("testnet", "./wallet.dat", "passwordtest");
        String selfDid = orangeProviderOntSdk.getSelfDID();
        System.out.println(selfDid);
    }


    @Test
    public void test3() throws Exception {
        OrangeProviderOntSdk orangeProviderOntSdk = OrangeProviderOntSdk.getOrangeProviderOntSdk("testnet", "./wallet.dat", "passwordtest");
        byte[] didPubkey = orangeProviderOntSdk.getDIDPubkey("did:ont:Af3r35XWVCmnXRfAkGEs2vSGfeZhS24NoT");
        System.out.println(didPubkey.length);
    }


    @Test
    public void test4() throws Exception {
        OrangeProviderOntSdk orangeProviderOntSdk = OrangeProviderOntSdk.getOrangeProviderOntSdk("testnet", "./wallet.dat", "passwordtest");
        String dataWithSig = "hello, world";
        byte[] sigBytes = dataWithSig.getBytes();
        byte[] msg = orangeProviderOntSdk.encryptDataWithDID(sigBytes, "did:ont:Af3r35XWVCmnXRfAkGEs2vSGfeZhS24NoT");

        byte[] msgBytes = orangeProviderOntSdk.decryptData(msg);
        System.out.println(new String(msgBytes));
    }


    @Test
    public void sigAndVertify() throws Exception {
        OrangeProviderOntSdk orangeProviderOntSdk = OrangeProviderOntSdk.getOrangeProviderOntSdk("testnet", "./wallet.dat", "passwordtest");
        assertNotNull(orangeProviderOntSdk);
        byte[] msg = "hello, baice".getBytes();
        byte[] signedData = orangeProviderOntSdk.signData(msg);
        String selfDid = orangeProviderOntSdk.getSelfDID();
        System.out.println(selfDid);
        Boolean aBoolean = orangeProviderOntSdk.verifySig(selfDid, msg, signedData);
        System.out.println(aBoolean);
        assertTrue(aBoolean);
    }


    @Test
    public void testEncrypt() throws Exception {
        OrangeProviderOntSdk orangeProviderOntSdk = OrangeProviderOntSdk.getOrangeProviderOntSdk("testnet", "./wallet.dat", "passwordtest");
        byte[] data = "this is a secret string !!!".getBytes();
        String userDID = orangeProviderOntSdk.getSelfDID();
        byte[] encryptedData = orangeProviderOntSdk.encryptDataWithDID(data, userDID);
        assertNotNull(encryptedData);
        byte[] decryptData = orangeProviderOntSdk.decryptData(encryptedData);
        System.out.println(new String(decryptData));


    }

}
