//
//  PublicKey.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 10/4/18.
//  Copyright © 2018 Essentia. All rights reserved.
//

import Foundation
import CryptoSwift
import secp256k1

public struct PublicKey {
    public let compressedPublicKey: Data
    public let uncompressedPublicKey: Data
    public let coin: Coin
    
    public init(privateKey: Data, coin: Coin) {
        self.compressedPublicKey = Crypto.generatePublicKey(data: privateKey, compressed: true)
        self.uncompressedPublicKey = Crypto.generatePublicKey(data: privateKey, compressed: false)
        self.coin = coin
    }
    
    public init(base58: Data, coin: Coin) {
        let publickKey = Base58.encode(base58)
        self.compressedPublicKey = Data(hex: publickKey)
        self.uncompressedPublicKey = Data(hex: publickKey)
        self.coin = coin
    }
    
    // NOTE: https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    public var address: String {
        switch coin {
        case .dogecoin: fallthrough
        case .bitcoin: fallthrough
        case .dash: fallthrough
        case .bitcoinCash: fallthrough
        case .litecoin:
            return generateBtcAddress()
        case .ethereum:
            return generateEthAddress()
        case .hdac:
            return generateHdacAddress()
        case .hdacTest:
            return generateHdacTestAddress()
        }
        
    }
    
    public var utxoAddress: Address {
        switch coin {
        case .bitcoin, .litecoin, .dash, .bitcoinCash, .dogecoin, .hdac, .hdacTest:
            return try! LegacyAddress(address, coin: coin)
        case .ethereum:
            fatalError("Coin does not support UTXO address")
        }
    }
    
    func generateBtcAddress() -> String {
        let prefix = Data([coin.publicKeyHash])
        let payload = RIPEMD160.hash(compressedPublicKey.sha256())
        let checksum = (prefix + payload).doubleSHA256.prefix(4)
        return Base58.encode(prefix + payload + checksum)
    }
    
    func generateCashAddress() -> String {
        let prefix = Data([coin.publicKeyHash])
        let payload = RIPEMD160.hash(compressedPublicKey.sha256())
        return Bech32.encode(prefix + payload, prefix: coin.scheme)
    }
    
    func generateEthAddress() -> String {
        let formattedData = (Data(hex: coin.addressPrefix) + uncompressedPublicKey).dropFirst()
        let addressData = Crypto.sha3keccak256(data: formattedData).suffix(20)
        return coin.addressPrefix + EIP55.encode(addressData)
    }

    func generateHdacAddress() -> String {
        let prefix = Data([coin.publicKeyHash])
        let payload = RIPEMD160.hash(compressedPublicKey.sha256())
        var checksum = (prefix + payload).doubleSHA256.prefix(4)
        checksum = swapUInt32Data(checksum)
        var hdacChecksum = "48444143".hexadecimal
        hdacChecksum = swapUInt32Data(hdacChecksum!)
        var result = Data.getxor(left: checksum, right: hdacChecksum!)
        result = swapUInt32Data(result)
        return Base58.encode(prefix + payload + result)
    }
    
    func generateHdacTestAddress() -> String {
        let prefix = Data([coin.publicKeyHash])
        let payload = RIPEMD160.hash(compressedPublicKey.sha256())
        var checksum = (prefix + payload).doubleSHA256.prefix(4)
        checksum = swapUInt32Data(checksum)
        var hdacChecksum = "48545354".hexadecimal
        hdacChecksum = swapUInt32Data(hdacChecksum!)
        var result = Data.getxor(left: checksum, right: hdacChecksum!)
        result = swapUInt32Data(result)
        return Base58.encode(prefix + payload + result)
    }
    
    public func get() -> String {
        return compressedPublicKey.toHexString()
    }
    
    public var data: Data {
        return Data(hex: get())
    }

    public func swapUInt32Data(_ data: Data) -> Data {
        var mdata = data // make a mutable copy
        let count = data.count / MemoryLayout<UInt32>.size
        mdata.withUnsafeMutableBytes { (i16ptr: UnsafeMutablePointer<UInt32>) in
            for i in 0..<count {
                i16ptr[i] =  i16ptr[i].byteSwapped
            }
        }
        return mdata
    }
}

extension String {
    var hexadecimal: Data? {
        var data = Data(capacity: count / 2)
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        guard data.count > 0 else { return nil }
        return data
    }
}
extension Data {
    static func getxor (left: Data, right: Data) -> Data {
        if left.count != right.count {
            NSLog("Warning! XOR operands are not equal. left = \(left), right = \(right)")
        }
        var result: Data = Data()
        var smaller: Data, bigger: Data
        if left.count <= right.count {
            smaller = left
            bigger = right
        } else {
            smaller = right
            bigger = left
        }
        let bs:[UInt8] = Array(smaller)
        let bb:[UInt8] = Array (bigger)
        var br = [UInt8] ()
        for i in 0..<bs.count {
            br.append(bs[i] ^ bb[i])
        }
        for j in bs.count..<bb.count {
            br.append(bb[j])
        }
        result = Data(br)
        return result
    }
}
