import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.InflaterInputStream

const val hex = "2e2e2e2e0000000313a112cf0000000000000460575a444601000000000003004c040000d0090000789ced9679681d5514c6efccbc99b7cf4cde56b33a79594d939837d9d3369aa55934c62e59cc6b1b93c6903c92466d1a696ba99fb1c5426b69419142295ae31f061304a31884c6d054a81aab28b5059552146b5b105a454968c633894b901495fe2142bfcb8f730f33f7cee5bb7738379b31c6131c211351849f8826e2895e6207f1095b78a994a8226a883a0b636bac8c7513bb883dc418b1cdb60096e00031b48861628af8809826be242e11ccce98ed26c884fa1bf3aaae6dca2ad0f502b6849a3ab7f6471eed6395eddb3a5943f78056d9d9a185742d9453a2e796e4e99a9ea3e73958635f647b43644b270b15e6e6161717e7e83a2b1f88f43ed2b99585b24345d97a3e63eb22035a55efc01391932f2d4cceb1e386835cb0b2612324647145c2d3c631e1f4dc5b827bee3c5f6bacb754dd9005d3e13c7691d7b97cb2dac21a8d3386cb88319a8de9b9e0dcda39f3f9a76cc6788e7b879d606d300c8609ea91f01e9b30f707edd473503cc146999b71946d8687e2c23a2c8b9a7493f6fb8a399acf6c0235c64442987f526f66dc49f61a779e25722adfcd1fe24f735dc217fc352187ffd192976258065333c4eff80cf1a09021ee4e6a10d560afa8a60d8b9fa55c108f5a2e887b93af52cea4bea480f4ad10908e2406a4c1d402fa789954146c922e8a07249f18b4a6d9caad87a5416b21376235ac23d6cb9a41e726c9164d0413fb6c998e29db5e7b895dd056db2fb9c2f653fc1bf60ae7acbd8b9bb53bb554478efb71c75772aef3557995d3a96e72eee5fb9d63c209e7b184af9dafa8df3b05759b6b2461c2d5a34eb866d4fdee67e307e574cf71b9267e44fe893f27ffecf945be162b2bef7b5b94fdfe0ea525ae4fb912b34319f51e5426a386280e29a165e34a7df4378a37f607e5b23aa3681e8bdaef4f51072dabd54074586d5bf6989a29bcabf6a81faa67d58d51bb9478cf2a25ddb3c57dddd361f1798f88b5de8f5d4f7967e536df21e7dbbe7dd2555fd891e93febaaf3f3629dff759b3b70447c2610748c075aadfb62d4b4a31a9de9349ff5dfeec162ffffeafddff9fe7ff75cf16cd66ec5f79e98eda97b62dbb59a60b5346718c66dfe3b5e7cd3678bdb99acee1af3d98cdbfac76abf7158b995f16d343ee9c9647537f9ce2d88ff130b67b27043584a3c6b368b35f3b151ef39d9fc17cddb0347f9ac5c208d07ccac743ea7cac0c26a3d5b8678a42107f7a1010f61235ad08c46ac4313c268c5c3d8840d588f075082bb711712a181030f0b2438a1221ab148422a32910d1d05588552546235eec54a14228414dc093fdc70c1063b64781080822878710782c8401e8a710faa703fea508b0a14211fb9c8c272a423190988430c7c70c00a110218ca508307b1166b508f6a946305f2d3ca326b8aaa969bde9df1bcec355d98dc19eee2c80779bec6a6b3d07c5cc92acdfa4ab2934509dc3a6f7ca4d41747a47651a4bcb5ff9475b19b3a294c4a205def28ccaba89c2c58f1c29525af36a69e9fdec07dfed1d41f9bf32b3d1978a813a112ce0000000000000ab0575a444601000000000003009c0a000020150000789cdd57797014551affe6486692ccd1339909994c8e21e4c2a44332392001b210200121e18a8009086d18e3c42121330c0bc1659fa81c2b2ac5b18a028b4b79e0b52aba8211d40d418ca8ab4895d65a5659bab5a094f7b12c9bf4fefacda413b2b0566db1ffecebfad5efbbdef77deff59bee9e4222d2021a200b4236301a10810a6033b017c8d213fd3396a8d240540f2c023c714467e3891a4c44fbcc444f02a780efa378dc02db301c06fe3c04f956a2fb05a2ef801f80a76d8801b212891ebb02740ea2a5c032808f295230e80b7a96fb029e8676886dab064d9e80e4a96987658e140a49ab5a7c570e9be76b5ed51ef44b03d6c908591b1a9a7d1ee648cbdb8343e7f9429ee9be70d017a2da1962b9d70bdf8aeea794f01032743fda3e248367aa14583534607a7b709532718132b39caa3c73a480145622e74b28e599160e74ef0ff825cf184f2d92f85bbaf70fd4f154f1184f1d5a1e345523a0590a4a48b5c01f90ba5f0e622a0a4a81802f280deb7b9ad275d454df1ebe74371a82d28a307a689308e26a5f28840457d829be375273f7a1e8524a8ad545a2c9f0d01d08e44e0bb504ba0f86fc97c91bb95168fb51c95327b562a32f0db964fbb0ac1016511d90da3ac27c21eab6425c1952426e94fc6be89211dd9588ec0b86fced6d34555ae5a3869bc39ea9be664fb1d7535c54e92da92c2df6788bbca5f1745d9b7f4d837f858f8ac7969454545414798ba93aec0f2cf705a9b8b0785ca1b76c30ef3c7fd8531308aff677ef8f14d4d027f24159e183743fd7e3e43efeab8ba1b76537bdcb7d07c8c16d4db28e9e95159bf2ab2ca173f2183e678de6a446b119757b0d3154cfe5fdb4ba7f82b6a44ff1df24dfdeaff06d7d193afc4268bf3cbe6facfc6aff56b988db9f94bf01ebd1c32e793da5d0fb9aafe8029de5b91fecfb2daf7da6bf909a78611de934e3d1512dfd8526705faeeeb87c8d6613efd54e2f727e59fe96f3457927cfe3a2d35cdf489b78cd0bf2326e5fde5fc03951bb93fb176b9770bd802ef62bb997501b9d97176b145b264de3be47e40b7c5d5dfdeb797d03f552a71ce0ebae94ef921f90bfe3b91ae9751e3f5393c06bc6d31e52faff4cb749eed7d4c867b579fda32889c93231914691c2252482cdac12fbabf06caac71c0b9b4b955c9f47b3c116361f7685afa379516e42750b5b4073799e45341f3b6a61d7d302e81af0128a25136b02cbb2962da1668a83be9416f1f9cbe87a4a80be8c24e83a26d1cd603d6ba6656481bd995aa0c7b09b6829d8ca5a6805efe7666a271be9d90aeae075db69259fb792525822ec1d94cad7e7c24c598e656958671219c0236037b1744ac3bd31b01cbe7e23bb8672388fa122b0c08ae81a72930d5cca752fe59332cf4bc9c811c74ac94b23c90e2e835de129c894c8ca302f8f1cac1c6744969d6c6cd45f41e5f02481c742f7802761c747b0095447c5e46413693cec19e05fa06206aba2899891c1264157ec93113f8e14ae819eccaa791e3b7832f757a37e2579d814ba169533d8343ecf059e0a4e6135348baad07b2dce9262afa519bc8fe93c9f87cdc47c25df4c9a0e76b359fc7ea7b23a9cf749e402cfa36a703dcde471f5b41099d370ff1722433a5b483ed8d3715f6f4486747623ceaf92d747cb3143613ff7fbe1af837f250550c184f557f1fe1b706ee6425f440db84cc8b718993d88bf85e7c9c79eca723cce69394e8c07e7741c4e9e89b5911b672a8139590ebf3f91e74b7af45a80abe90a979e476a71e9201bc8887349c89d8afbde887944193823b960335971d69467d11fb3f1c6ceb940c19c0acd8eec266d697650a7cf3eaa4bccf95e7f577652ec3739e5b142eed6d8c49c0ec331b36c1072cf18f5891f1b6f88f3c6cb86b0f380ed6fc9cf09235d998656b7135f084fa0894d78c35fc41bbccf9d85ef870fd389f678845c21b73306b36df3e9bcfb4d9a953ebce616ddeec481ba4763ea04a5f640ddbd864e4ba9718241a93d505f416efcd7bc0f058be33fb07f92f06c7ca969734287f98870d0fc92e919f351c70be67af3018b64efb5dc655d69ed151eb7b65abbad99c24fd61396546183658d30d97cab70c6f486b0cef49e70d26ab6fddd72ccf64bf3799bd71a6f676693fdb425d15e133fc7feb0a9db9e64a972345b6b9d59e626e79b6665fd0a0e241db6bc9074312e6344a5e1e311dbada39337d89625a75ada92b71942c977f03d52a071155ab5aeb37cbf146c75fd687bc45560ef75fd2eee2757a3cd9cf2ae7974caf3a6d2942db1135216dab6a7bc9bb82b65be49d95b051fb96da9275297db7e4afd38ae202d9cdc90deeccec87ec5d62fcbf2d5c4967d1fd8b66d3409539f7718bfd8dd25dc7ec8614c82bc1ed808dc0a7c0e7bee1c97491e368e3ded300ec89f3e70dc3cd497f60787f1ad6d5d8222af5b1fe1ef9f72187f782a32a71a79ef0c2f346f479c0335ef802cc2777e47975000fe029cbbb54b1805e4002d7777090b11f72bc8b9dbbb84d3a8bdf69e2e6122ec13807cd8c6edea126e008f07af83ef37c8b9053a7b0e6bc1dc8b3b237ddc0bbb15fa78ac7b0af023eaedd9d4256c867d22f4c25f47e20ec1d6893ec644f53bd1b308b906b807b145e0b5f0af063ebab74bf022febeb559c2811d91f847c0699d59c2e2cd5d4223f6c2063915580f5d1319da2118ae6ba3e6411dbf762e721ea2abb68178edbfa71acca58f108135c6e86485b4dc35d8863ea21ba3321ffa687ead2aaaf13cef90fc9c951c4a2c0dda55df403e63649e76203e0aa5ae3e5a87d722b57db5377dd4a0b071b0bd480eb516fef5a89f8b3acd80e454a55ed5fb9a2a7dad4a5bd5b8af54e919d57baf2a19b403d22e356e700c7630f732990727e4a8924395d6a9eea5aaad4ab5e5ab5248f51e506de3559ba4da8ea8d23baaf4912a3da4ce9871997544bac59f417c4118c984f78e8304bc6864831eef17237c02e9133bf08ec834d89995595802333381d95822d3302d8b654616c74c2c9e19580cd3331d2356519a34326b748698eac974e12197eece4873a739c47c575c9eec76a7ca05c56972664c8961a49c1533267bb4bb26bbac6c46514d7e5e7ef5c404ab2c270c7b32992dc39f549719f64b557d7254d0d89051affdf904446fdb1f4a54f6e3b5cec616fc0bc0379fb23779f826527802be3170defee330fc17c36a15843865d0ef833d86134f88ce1ee0c15ed1d9764a743e006e05974d4b767cbeb2c7e03b2c3aa70095d02781f73c293a5bc07bc115b03d087e09e802f601e75e149d678e8bceeb8e884e4b4b958381b3c039c06d90df87eff1d3a2f351e031e010723c0754b5f61876dfd26308047a0c052744e77be86d3162cfa187bbc1991d3d06f115d17902fac963a2f33e7f8f611f6c85b0798152e0ab5745e761f097af8bceb380807ce7c0b3ba45e79c3f89ce83f03f0c6c38293adfc41a4f02b321cf856f16f876e00dd88ea1c6e44ffbacad6f88ce89e03e702d78538fe8bc08792ef6683e300a6bfa12f9ae45ffb58001b63940ee4d7f4d1a0d7d37e4cd98b3e6b31dc2e57f09576f343636d678878f3c05445e6f048d798d5c5346630daee8481f36947cc36d3f377e6e86e21fe875309e68cad4d7ca3f48aa1bfbbfde9fffc771b943255cc13e74f4eeba5e53f07693e6dbb79a3446f04ef0a7c06cc8db8a9ab59d7bc76acbc0a5c0e931cddaf74f1dd7948acdda0ae83588390adb2bc07ee008f021b011d80184817f00770077027d8006f3e2807720b7025f9c6abac29be1ea8cabfecc740c3e33ff059f5d356a13a112d00000000000000567575a4446010000000000030053050000300a0000789cdd957d6c535514c0cf7bafedebf7ba7eacfb2c6fac5b191fdbda6e635f4191c1821a2103a64816e868d93ab66e7414c1819c0462cc2241121482ec43830e3520c8201350d039638cc6a9fca13241934548c4006ab23f843ecf7b1da3cc8d10fff00fcfed2fe7bc73ef3df79e7b6fefcd030096608895442de12302443bf1197185e8a3067e6af83a716c8c430a80fd2a801b44310f5049f8896f880b04a8ff899e70c65146ec25de268e10c3c40851a101786a0a4244eb18b2542dae9953ecf114c3025f381c080bfe80d0e4139636f9067a7d777c4fb44462e6c640d827d404a9f26c38aec3329f3f120e0d1c1196faea070eb7c144991f0e84b6b4097ed7c2e6d696b07fa0877c3581705bb0250495be8d0158de10112a036b05b74770179479bc65856ec153e029d4c28a5070f3f2607300dc73bdded2d2d2028f1b1e89049bfc8130b8f3dc25799ea2c9e2570723c2a2a6c8a6a03c16edd07cf10d46d27dd1764ed216381d95766f5dd4c8fe79cb4e6d54d0057db083ddc69c57dd603be134cc121fe32a6eb1b4531cf4c243f01c5c8277158da2d4bf171a19c9bf560c477746cf4433c40f64ff1208c8e3bc0a5e518a3f2c5e15df116be4ba46e667d9b743ac12dbc11f95fa0f6b0fdddace5c882e673a44690ebb19bb58cd56ddfe945aa530bf89a7e0189431f9720e99705eac855214451657cba78dc53a584d11590c401d8822905e0734616c25ad927544f657600468cbb1864ea70918ea570f56e0701d9ddc24faaea738a2a820dd20eb0628c75450620836403ad5b740081cb28ed03c188adb0259a4e7e24ac8215d866ba89f8abe423093be4bb016dca46307403d56ac5492a6287784a5f92ba9a8a4f9838d760ac00066e0a195ddad7a9375aa8fb361858a5ba5a9e2be57547321fe3d6e81e62a7791b328ded73628026c9b22a8d5285d4ca13259d7a4048828bb98edca14e8518eeaaed1f77ad5755d333fc7f01dff8a7e447dd050a0c930a8753b896b866e7d1fe135d6199b0cbb8c594655a2cdb028f1aca1d3bc2ce743b3c9956b795ebfc2c6389eb4fda8afb38deace25995cf3ec9539e5c909fab3c9a0db98ba47bb3df561dde3e907341fa79bb5fb33f6aa6b8525aa6dc249de3a3d459999754359e24ce70e64ffc195e79c624caedfc1e4d2d2992c495941f17b8851abc9c5d94dae1752e15fe51c9fef83e4ea35fe64bf93efb7269f353ee72ef3991c29e70ecb68d662dbcd6c29f7f8fcfb6d7353a2b6663b24f53aaf275d764eb616d3d24612f6a531897d6907ad0bd3478df16b7329233ff17eeb131545f1ffcae851ab7a46cf504226b1b57b2821ff8855bde6f69e04f13f90aaaea1f1710e1eb7aae3eb727b6275bb687edbba63f6d6a377dbb4935dd36755bf483ab0eb07ed64f13751fc4e8adb4574c48d25c9be13f78e37519898b07761997b35a3907f32ec98cd3277fbc9be38a74a6e1c7ba9274aeeb8e518b7b4e356f9243d622f8af4f2f3744f79e886b282d7d8ca9a5c528d92ea4cf49fee34cfb3338ee9380d05ccc61c346002ea50832c0232c8a11a4d68411b26632aa6a303b3d085337136e6a31bbd588c4558881e2cc03c9c83b3301767a013333103d33005ed98845634a31eb5a842252a90472326d26d3bdb315def14b2739dceecccd945452e693d1dc9fa7bd6d79e16d343e6d7a4cb153e7af6e97a865e07a39cd70cbab7255d0195a4b931e1e344430fc9d593fd962bc4e1a641bebb7190bf181ee48789738483a9b6b027fa2d7fad1fe40d6d83fc5b547f49fd8bee32b185fc9b89cf370cf28a9641beb4afdff215c1913d42f1a6586e593c1364ea960e47f9cbbf16dffc5a577cbf780f2aa6497c7bbf5cc55cf8e213262ff028bbfb199e7592ce265e227baa387f03b0107f8d"

// tile size = 0x18

fun main() {
    val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val bbuf = ByteBuffer.wrap(bytes)
        .order(ByteOrder.BIG_ENDIAN)

    val magic = bbuf.int
    val tilesCount = bbuf.int

    if (magic != 0x2e2e2e2e) {
        throw IllegalArgumentException("Invalid magic number")
    }

    println("Tiles count: $tilesCount")

    for (i in 0 until tilesCount) {
        val id = bbuf.int
        val line = bbuf.int // line?
        val size = bbuf.int

        println()
        println("tile $i: id: $id, line: $line, size: $size")

        val tileBbuf = bbuf.slice().order(ByteOrder.LITTLE_ENDIAN)

        val signature = tileBbuf.int // WZDF
        if (signature != 0x46445a57) {
            throw IllegalArgumentException("Invalid tile signature")
        }

        val endianness = tileBbuf.int
        if (endianness != 1) {
            throw IllegalArgumentException("Invalid tile endianness")
        }

        val version = tileBbuf.int
        if (version != 0x30000) {
            throw IllegalArgumentException("Invalid tile version")
        }

        val dataFileSize = tileBbuf.int
        val decompressedSize = tileBbuf.int
        val compressedBytes = ByteArray(dataFileSize).apply { tileBbuf.get(this) }

        val decompressedBytes = InflaterInputStream(compressedBytes.inputStream()).use { it.readBytes() }
        if (decompressedBytes.size != decompressedSize) {
            throw IllegalArgumentException("Invalid decompressed size")
        }

        println(decompressedBytes.joinToString("") { it.toInt().and(0xff).toString(16).padStart(2, '0') })

        handleUncompressedTile(decompressedBytes)

        bbuf.position(bbuf.position() + size)
    }

    println("remaining bytes: ${bbuf.remaining()}")
}

fun handleUncompressedTile(bytes: ByteArray) {
    val decompressedBbuf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

    val itemCount = decompressedBbuf.int
    val padBits = decompressedBbuf.int

    val block1Offset = 8 // header
    val block2Offset = 8 + (itemCount * 4) // header + item sizes

    val padMask = (0xffffffff shl (padBits % 32)).toInt()
    val pad = padMask.inv()

    fun getItem(itemIndex: Int, itemSize: Int): Pair<Int, Int> {
        val previousAccSizeOffset = block1Offset + ((itemIndex - 1) * 4)
        val accSizeOffset = block1Offset + (itemIndex * 4)

        val previousAccSize = if (itemIndex == 0) 0 else decompressedBbuf.getInt(previousAccSizeOffset)
        val accSize = decompressedBbuf.getInt(accSizeOffset)

        val previousAccSizeWithPad = (previousAccSize + pad) and padMask
        val itemsOffset = block2Offset + previousAccSizeWithPad
        val itemsSize = accSize - previousAccSizeWithPad
        val itemCount = itemsSize / itemSize

        return itemsOffset to itemCount
    }

    // line/data
    val lineData = getItem(9, 8)
    // line/summary
    val lineSummary = getItem(10, 62)
    // point/data
    val pointData = getItem(13, 4)
    // point/id
    val pointId = getItem(14, 4)
    // shape/data
    val shapeDAta = getItem(8, 4)
    // string
    val string1 = getItem(0, 1)
    if (string1.second > 0) {
        val string1Offset = string1.first
        val string1Bytes = ByteArray(string1.second).apply { decompressedBbuf.position(string1Offset); decompressedBbuf.get(this) }
        println("string1: ${String(string1Bytes).replace("\u0000", " ")}")
    }
    val string2 = getItem(1, 1)
    if (string2.second > 0) {
        val string2Offset = string2.first
        val string2Bytes = ByteArray(string2.second).apply { decompressedBbuf.position(string2Offset); decompressedBbuf.get(this) }
        println("string2: ${String(string2Bytes).replace("\u0000", " ")}")
    }
    val string3 = getItem(2, 1)
    if (string3.second > 0) {
        val string3Offset = string3.first
        val string3Bytes = ByteArray(string3.second).apply { decompressedBbuf.position(string3Offset); decompressedBbuf.get(this) }
        println("string3: ${String(string3Bytes).replace("\u0000", " ")}")
    }
    val string4 = getItem(3, 1)
    if (string4.second > 0) {
        val string4Offset = string4.first
        val string4Bytes = ByteArray(string4.second).apply { decompressedBbuf.position(string4Offset); decompressedBbuf.get(this) }
        println("string4: ${String(string4Bytes).replace("\u0000", " ")}")
    }
    val string5 = getItem(4, 1)
    if (string5.second > 0) {
        val string5Offset = string5.first
        val string5Bytes = ByteArray(string5.second).apply { decompressedBbuf.position(string5Offset); decompressedBbuf.get(this) }
        println("string5: ${String(string5Bytes).replace("\u0000", " ")}")
    }
    val string6 = getItem(5, 1)
    if (string6.second > 0) {
        val string6Offset = string6.first
        val string6Bytes = ByteArray(string6.second).apply { decompressedBbuf.position(string6Offset); decompressedBbuf.get(this) }
        println("string6: ${String(string6Bytes).replace("\u0000", " ")}")
    }
    val string7 = getItem(6, 1)
    if (string7.second > 0) {
        val string7Offset = string7.first
        val string7Bytes = ByteArray(string7.second).apply { decompressedBbuf.position(string7Offset); decompressedBbuf.get(this) }
        println("string7: ${String(string7Bytes).replace("\u0000", " ")}")
    }
    val string8 = getItem(7, 1)
    if (string8.second > 0) {
        val string8Offset = string8.first
        val string8Bytes = ByteArray(string8.second).apply { decompressedBbuf.position(string8Offset); decompressedBbuf.get(this) }
        println("string8: ${String(string8Bytes).replace("\u0000", " ")}")
    }
    // line_route/data
    val lineRouteData = getItem(15, 4)
    // street/name
    val streetName = getItem(16, 10)
    // street/city
    val streetCity = getItem(17, 4)
    // TODO: Original code decreases streetCity.second by 1, but it's not clear why
    // street/id
    // TODO: If itemCount of the tile is less than 38, street_id is not read
    val streetId = getItem(37, 4)
    // polygon/head
    val polygonHead = getItem(18, 16)
    // polygon/point
    val polygonPoint = getItem(19, 2)
    // line_speed/avg
    val lineSpeedAvg = getItem(21, 2)
    // line_speed/line_ref
    val lineSpeedLineRef = getItem(20, 4)
    // TODO: If lineSpeedLineRef.second is 0, line_speed/index is not read and range is read, otherwise line_speed/index is read and range is not read
    // range
    val range = getItem(24, 6)
    // alert/data
    val alertData = getItem(25, 16)
    // square/data
    val squareData = getItem(26, 12)
    // metadata/attributes
    val metadataAttributes = getItem(27, 8)
    // venue/head
    val venueHead = getItem(28, 16)
    // venue/venueid
    val venueVenueId = getItem(29, 2)
    // TODO: If itemCount of the tile is less than 31, skip _fill_line_ext
    // line_ext/type
    val lineExtType = getItem(30, 1)

    // TODO: If lineSpeedLineRef.second is not 0, jump to here and skip the previous code
    // line_speed/index
    val lineSpeedIndex = getItem(22, 4)
    // line_speed/index
    val lineSpeedIndex2 = getItem(23, 2)

}