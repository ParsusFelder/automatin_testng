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
 * @Description: 本地摘要运算
 * <p>用例覆盖点：</p>
 * <p>1）本地做摘要，摘要算法为MD5/SHA1/SHA224/SHA256/SHA384/SHA512/SM3</p>
 * <p>2）本地做摘要，摘要算法为md5/sha1/sha224/sha256/sha384/sha512/sm3</p>
 * <p>3）本地做摘要，原文为null</p>
 * <p>4）本地做摘要，摘要为空或null</p>
 * <p>5）本地做摘要，大原文摘要</p>
 * <p>6）本地做摘要，摘要算法错误</p>
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
     * 本地做摘要，摘要算法为MD5/SHA1/SHA224/SHA256/SHA384/SHA512/SM3
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 本地做摘要，摘要算法为md5/sha1/sha224/sha256/sha384/sha512/sm3
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 本地做摘要，原文为null
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }

    /**
     * 本地做摘要，摘要为空或null
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }
    /**
     * 本地做摘要，大原文摘要
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }
    /**
     * 本地做摘要，摘要为空或null
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
                Assert.fail("本地做摘要运算失败：" + digest.getReturnCode());
            }
        } catch (Exception e) {
            Assert.fail("本地做摘要运算失败：" + digest.getReturnCode() + e.getMessage());
        }
    }
}
