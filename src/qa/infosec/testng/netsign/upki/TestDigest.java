package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
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
 * @ClassName: TestDigest
 * @date 2020-03-04 17:45
 * @Description: ����ժҪ����
 * <p>�������ǵ㣺</p>
 * <p>1��������ժҪ��ժҪ�㷨ΪMD5/SHA1/SHA224/SHA256/SHA384/SHA512/SM3</p>
 * <p>2��������ժҪ��ժҪ�㷨Ϊmd5/sha1/sha224/sha256/sha384/sha512/sm3</p>
 * <p>3��������ժҪ��ԭ��Ϊnull</p>
 * <p>4��������ժҪ��ժҪΪ�ջ�null</p>
 * <p>5��������ժҪ����ԭ��ժҪ</p>
 * <p>6��������ժҪ��ժҪ�㷨����</p>
 */
@Test(groups = "abcjew.digest")
public class TestDigest {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
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
    }

    /**
     * ������ժҪ��ժҪ�㷨ΪMD5/SHA1/SHA224/SHA256/SHA384/SHA512/SM3
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal", dataProvider = "alg", dataProviderClass = NetSignDataProvider.class)
    public void testDigest_01(String sDigestAlg) {
        System.out.println("Test sDigestAlg Normal");

        byte[] pMsg = Utils.getRandomString(64).getBytes();
        UpkiResult digest = null;
        try {
            digest = agent.digest(pMsg, sDigestAlg);
            if (digest == null || digest.getReturnCode() != 0) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ������ժҪ��ժҪ�㷨Ϊmd5/sha1/sha224/sha256/sha384/sha512/sm3
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal", dataProvider = "alg", dataProviderClass = NetSignDataProvider.class)
    public void testDigest_02(String sDigestAlg) {
        System.out.println("Test sDigestAlg Normal");

        byte[] pMsg = Utils.getRandomString(64).getBytes();
        UpkiResult digest = null;
        String alg = sDigestAlg.toLowerCase();

        try {
            digest = agent.digest(pMsg, alg);
            if (digest == null || digest.getReturnCode() != 0) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ������ժҪ��ԭ��Ϊnull
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal")
    public void testDigest_03() {
        System.out.println("Test sDigestAlg PlainText Null");

        byte[] pMsg = null;
        UpkiResult digest = null;
        String alg = "SHA1";

        try {
            digest = agent.digest(pMsg, alg);
            if (digest != null && digest.getReturnCode() != -1023) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ������ժҪ��ժҪΪ�ջ�null
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal", dataProvider = "emptys-parameter", dataProviderClass = NetSignDataProvider.class)
    public void testDigest_04(String sDigestAlg) {
        System.out.println("Test sDigestAlg DigestAlg Null or Empty");

        byte[] pMsg = Utils.getRandomString(64).getBytes();
        UpkiResult digest = null;

        try {
            digest = agent.digest(pMsg, sDigestAlg);
            if (digest != null && digest.getReturnCode() != -1023) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }
    /**
     * ������ժҪ����ԭ��ժҪ
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal", dataProvider = "alg", dataProviderClass = NetSignDataProvider.class)
    public void testDigest_05(String sDigestAlg) {
        System.out.println("Test sDigestAlg PlainText Big");

        byte[] pMsg = ParseFile.getFileData(ParameterUtil.bigfilepath);
        UpkiResult digest = null;
        try {
            digest = agent.digest(pMsg, sDigestAlg);
            if (digest == null || digest.getReturnCode() != 0) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }
    /**
     * ������ժҪ��ժҪΪ�ջ�null
     * @param sDigestAlg
     */
    @Test(groups = "abcjew.digest.normal")
    public void testDigest_06() {
        System.out.println("Test sDigestAlg DigestAlg Error");

        byte[] pMsg = Utils.getRandomString(64).getBytes();
        UpkiResult digest = null;
        String sDigestAlg = "123";
        try {
            digest = agent.digest(pMsg, sDigestAlg);
            if (digest != null && digest.getReturnCode() != -1023) {
                Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("������ժҪ����ʧ�ܣ�" + digest.getReturnCode() + e.getMessage());
        }
    }
}
