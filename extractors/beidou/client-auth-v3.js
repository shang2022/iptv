/** 云盛京 Android 3.0.7 / versionCode 107 的公开客户端 v3 配置解码材料。
 * 来源：应用宝 com.taihe.sjtvim，APK MD5 9b5cd75420ce2c2a140a94c69f189ab8。
 * 由包内 libcoder-lib.so 的 rsaLiveDecoder(version=3) 实测核对；不是用户私钥或账号凭据。
 * 这里只保存客户端内置材料，不保存服务器动态下发的 Referer、pullKey 或播放签名。
 */
import { createPrivateKey } from 'node:crypto'

export const CLIENT_KEY_V3 = createPrivateKey({
  key: Buffer.from([
    'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOJqGLjxxzgHtkmT',
    'oON4WPgfhqmwrt13oMEFLIQKgdZa5/H916WzbBDkoSalSLQpOevGL3nKiU+ECZqL',
    '3QD+J0TYBttNup/qA+d9fU4njxRu8eXZ5LYwl7TzxMsTIyf89Xh7OCjP6pthxVql',
    '1tphX5GZrqMNZbOMiw/rK8Pg/PCBAgMBAAECgYAaAQN74lD2L3SROMJmvcDCJqTJ',
    'woAi8YVmBdkaBTbqTqCLG5Nz9Yp42jlj/eG+x2lemfGD9G4W0txjgqLMZWRO/Xp6',
    'WHs+7+L2IX1DfduhJcnFjGkv4WWgwgVUskasZhR41tMVqpTcgkzB+PELuw2NaJjY',
    'yiyR9FNw3xSQPes60QJBAP4qWbep+06AfIuOA66AiHe7axN53HKOQTzjw6Cn4yRs',
    'J45L+F7YpMtAzcabolNnFpJCvBKiO6MpfW0WvHhAQH0CQQDkDHewvlKI4PsrgHM2',
    'u0D90EymbBCmaoOKmARu//TcUOURHOBKE2N8QJZWVjwZN/aV4mrFY2IdO/vFwydc',
    '61NVAkEAj67vYzXz/NAEGHyjNi4xd8Z65Nq6NgSXes2j1Rmz/e4qenYWJcBBgSnU',
    'apenL5ESoIKbgck2/6k/38C/sRdZnQJAQimz2B1/yKKtfJOJ2ck+M+VpN6eGtSGW',
    'BHHSZ3nvSrRVoT9le1hgtr3uYCIo0ZBBBH9qRtZsstqiU2ApXXYQ+QJABGF7U0R5',
    'W81CPtN1qTt+cU4pDsvIIhvv35BM2Nk15Cj62HPkLQmwvZK1F+7n4gDQXLWqekoM',
    'Rk87yN4rDV9Waw==',
  ].join(''), 'base64'),
  format: 'der', type: 'pkcs8',
})
