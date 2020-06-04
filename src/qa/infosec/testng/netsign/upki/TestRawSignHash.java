package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.util.Base64;
import org.testng.Assert;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestRawSignHash
 * @date 2020-03-19 14:09
 * @Description: RAWǩժҪ
 * <p>�������ǵ㣺</p>
 * <p>1��RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����</p>
 * <p>2��RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����</p>
 * <p>3��RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����</p>
 * <p>4��RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����</p>
 * <p>5��RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����</p>
 * <p>6��RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����</p>
 * <p>7��RawǩժҪ��rawSignHash��:DN�ջ�null</p>
 * <p>8��RawǩժҪ��rawSignHash��:ժҪΪ�ջ�null</p>
 * <p>9��RawǩժҪ��rawSignHash��:Base64��ǩ��ժҪΪ�ջ�null</p>
 */
@Test(groups = "abcjew.rawsignhash")
public class TestRawSignHash {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // ����netsignconfig.properties�����ļ�����ȡ������Ϣ,confpath=null ʹ��Ĭ��·��
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     * @param dn  RSA֤��DN������֤��DN
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_01(String alg, String dn) {
        System.out.println("RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷΪString����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            System.out.println(upkiResult.getResults());
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     * @param dn  RSA֤��DN������֤��DN
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_02(String alg, String dn) {
        System.out.println("RawǩժҪ��rawSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷΪbyte[]����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_03(String alg, String sn) {
        System.out.println("RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷΪString����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_04(String alg, String sn) {
        System.out.println("RawǩժҪ��rawSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷΪbyte[]����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ��ΪString����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_05(String alg, String bankcode) {
        System.out.println("RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷΪbyte[]����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ��Ϊbyte[]����
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_06(String alg, String bankcode) {
        System.out.println("RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷΪbyte[]����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }
    
    /**
     * RawǩժҪ��rawSignHash��:DN�ջ�null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_07(String dn) {
        System.out.println("RawǩժҪ��rawSignHash��:DN�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg = "SHA1";
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:ժҪΪ�ջ�null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_08(String alg) {
        System.out.println("RawǩժҪ��rawSignHash��:ժҪΪ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg1 = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            byte[] digest = Utils.getDigest(alg1, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * RawǩժҪ��rawSignHash��:Base64��ǩ��ժҪΪ�ջ�null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_09(String digestData) {
        System.out.println("RawǩժҪ��rawSignHash��:Base64��ǩ��ժҪΪ�ջ�null");

        UpkiResult upkiResult;
        String alg = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != -100101 && upkiResult.getReturnCode() != -1011) {
                Assert.fail("RawǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

}
