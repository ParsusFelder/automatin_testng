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
 * @Description: RAW签摘要
 * <p>用例覆盖点：</p>
 * <p>1）Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确，为String类型</p>
 * <p>2）Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确，为byte[]类型</p>
 * <p>3）Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确，为String类型</p>
 * <p>4）Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确，为byte[]类型</p>
 * <p>5）Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确，为String类型</p>
 * <p>6）Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确，为byte[]类型</p>
 * <p>7）Raw签摘要（rawSignHash）:DN空或null</p>
 * <p>8）Raw签摘要（rawSignHash）:摘要为空或null</p>
 * <p>9）Raw签摘要（rawSignHash）:Base64待签名摘要为空或null</p>
 */
@Test(groups = "abcjew.rawsignhash")
public class TestRawSignHash {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // 解析netsignconfig.properties配置文件，获取所需信息,confpath=null 使用默认路径
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
     * Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确，为String类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     * @param dn  RSA证书DN、国密证书DN
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_01(String alg, String dn) {
        System.out.println("Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确为String类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            System.out.println(upkiResult.getResults());
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确，为byte[]类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     * @param dn  RSA证书DN、国密证书DN
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-dn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_02(String alg, String dn) {
        System.out.println("Raw签摘要（rawSignHash）:DN，摘要，Base64待签名摘要正确为byte[]类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确，为String类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_03(String alg, String sn) {
        System.out.println("Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确为String类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确，为byte[]类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-sn", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_04(String alg, String sn) {
        System.out.println("Raw签摘要（rawSignHash）:SN，摘要，Base64待签名摘要正确为byte[]类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, sn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确，为String类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_05(String alg, String bankcode) {
        System.out.println("Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确为byte[]类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确，为byte[]类型
     *
     * @param alg RSA摘要算法、国密摘要算法
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "all-alg-bankcode", dataProviderClass = NetSignDataProvider.class)
    public void testRawSignHash_06(String alg, String bankcode) {
        System.out.println("Raw签摘要（rawSignHash）:Bankcode，摘要，Base64待签名摘要正确为byte[]类型");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            upkiResult = agent.rawSignHash(digest, bankcode, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }
    
    /**
     * Raw签摘要（rawSignHash）:DN空或null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_07(String dn) {
        System.out.println("Raw签摘要（rawSignHash）:DN空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg = "SHA1";
        try {
            byte[] digest = Utils.getDigest(alg, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:摘要为空或null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_08(String alg) {
        System.out.println("Raw签摘要（rawSignHash）:摘要为空或null");

        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult;
        String alg1 = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            byte[] digest = Utils.getDigest(alg1, plainText);
            String digestData = Base64.encode(digest);
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != 0 || upkiResult.getResults() == null) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

    /**
     * Raw签摘要（rawSignHash）:Base64待签名摘要为空或null
     */
    @Test(groups = "abcjew.rawsignhash.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testRawSignHash_09(String digestData) {
        System.out.println("Raw签摘要（rawSignHash）:Base64待签名摘要为空或null");

        UpkiResult upkiResult;
        String alg = "SHA1";
        String dn = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.rawSignHash(digestData, dn, alg);
            if (upkiResult.getReturnCode() != -100101 && upkiResult.getReturnCode() != -1011) {
                Assert.fail("Raw签摘要失败：" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("Raw签摘要失败：" + e.getMessage());
        }
    }

}
