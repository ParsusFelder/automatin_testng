package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import cn.com.infosec.util.Base64;
import org.testng.Assert;
import org.testng.Reporter;
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
 * @ClassName: TestDetatchedSignHash
 * @date 2020-03-20 18:13
 * @Description: DetachedǩժҪ
 * <p>�������ǵ㣺</p>
 * <p>1��DetachedǩժҪ��detachedSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ</p>
 * <p>2��DetachedǩժҪ��detachedSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ</p>
 * <p>3��DetachedǩժҪ��detachedSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ</p>
 * <p>4��DetachedǩժҪ��detachedSignHash��:DN�ջ�null</p>
 * <p>5��DetachedǩժҪ��detachedSignHash��:ժҪΪ�ջ�null</p>
 * <p>6��DetachedǩժҪ��detachedSignHash��:Base64��ǩ��ժҪΪ�ջ�null</p>
 */
public class TestDetatchedSignHash {
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
     * DetachedǩժҪ��detachedSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷ
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     * @param dn  RSA֤��DN������֤��DN
     */
    @Test(groups = "abcjew.detachedsignhash.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testDetachedSignHash_01(String alg, String dn) {
        System.out.println("DetachedǩժҪ��detachedSignHash��:DN��ժҪ��Base64��ǩ��ժҪ��ȷΪString����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("DetachedǩժҪ��detachedSignHash��������֤�鲻֧��SHA1ժҪ�㷨");
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * DetachedǩժҪ��detachedSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷ
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.detachedsignhash.normal", dataProvider = "all-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testDetachedSignHash_02(String alg, String sn) {
        System.out.println("DetachedǩժҪ��detachedSignHash��:SN��ժҪ��Base64��ǩ��ժҪ��ȷΪString����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("DetachedǩժҪ��detachedSignHash��������֤�鲻֧��SHA1ժҪ�㷨");
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }
    /**
     * RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷ
     *
     * @param alg RSAժҪ�㷨������ժҪ�㷨
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testDetachedSignHash_03(String alg, String bankcode) {
        System.out.println("RawǩժҪ��rawSignHash��:Bankcode��ժҪ��Base64��ǩ��ժҪ��ȷΪbyte[]����");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                if (upkiResult.getReturnCode() != -100004 && !"SHA1".equals(alg)) {
                    Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("DetachedǩժҪ��detachedSignHash��������֤�鲻֧��SHA1ժҪ�㷨");
            }
        } catch (Exception e) {
            Assert.fail("RawǩժҪʧ�ܣ�" + e.getMessage());
        }
    }
    /**
     * DetachedǩժҪ��detachedSignHash��:DN�ջ�null
     */
    @Test(groups = "abcjew.detachedsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedSignHash_04(String dn) {
        System.out.println("DetachedǩժҪ��detachedSignHash��:DN�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg = "SHA1";
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * DetachedǩժҪ��detachedSignHash��:ժҪΪ�ջ�null
     */
    @Test(groups = "abcjew.detachedsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedSignHash_05(String alg) {
        System.out.println("DetachedǩժҪ��detachedSignHash��:ժҪΪ�ջ�null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg1 = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            byte[] digest = Utils.getDigest(alg1, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * DetachedǩժҪ��detachedSignHash��:Base64��ǩ��ժҪΪ�ջ�null
     */
    @Test(groups = "abcjew.detachedsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDetachedSignHash_06(String digestData) {
        System.out.println("DetachedǩժҪ��detachedSignHash��:Base64��ǩ��ժҪΪ�ջ�null");

        UpkiResult upkiResult;
        String alg = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.detatchedSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != -100101 && upkiResult.getReturnCode() != -1011) {
                Assert.fail("DetachedǩժҪʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("DetachedǩժҪʧ�ܣ�" + e.getMessage());
        }
    }

}
