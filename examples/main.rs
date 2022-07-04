use std::f64::MAX;
use std::time::Instant;
use rand_core::OsRng;

use suter_proofs::confidential::ConfidentialTransaction;
use suter_proofs::confidential::Transaction;
use suter_proofs::{Amount, PublicKey, SecretKey};


fn test(a:u64,b:u64){
    let mut csprng = OsRng;
    let sender_sk = SecretKey::generate_with(&mut csprng);
    let sender_pk = sender_sk.to_public();
    println!("测试suter_proof加密:\n");
    println!("准备加密数字{}",a);
    let start = Instant::now();
    let ctx1 = a.encrypt_with(sender_pk);
    println!("获取加密结果ctx1");
    let elapsed = start.elapsed();
    println!("用时{}秒",elapsed.as_secs()); 

    println!("准备加密数字{}",b);
    let start = Instant::now();
    let ctx2 = b.encrypt_with(sender_pk);
    println!("获取加密结果ctx2");
    let elapsed = start.elapsed();
    println!("用时{}秒",elapsed.as_secs());
    
    println!("准备计算{}+{}",a,b);
    let start = Instant::now();
    let ctx3 = ctx1 + ctx2;
    let elapsed = start.elapsed();
    println!("用时{}秒",elapsed.as_secs());
    println!("获取结果ctx3");


    println!("准备解密ctx3");
    let start = Instant::now();
    let decrypted = u64::try_decrypt_from(&sender_sk,ctx3).unwrap();
    let elapsed = start.elapsed();
    println!("获取解密结果:{:?}",decrypted);    
    println!("用时{}秒",elapsed.as_secs());

}


fn main() {
    test(1,2);
    test(1<<15, 1<<15);
    test(1<<26, 1<<25);
    println!("测试交易proof生成");
    let mut csprng = OsRng;
    let sender_sk = SecretKey::generate_with(&mut csprng);
    let sender_pk = sender_sk.to_public();
    let max_32 = u64::from(std::u16::MAX);
    let receiver_initial_balances: Vec<u64> = vec![1,9 , 100];
    let transaction_values: Vec<u64> = vec![8, 88, 888];
    let receivers_info: Vec<_> = receiver_initial_balances
        .iter()
        .map(|receiver_initial_balance| {
            let receiver_sk = SecretKey::generate_with(&mut csprng);
            let receiver_pk = receiver_sk.to_public();
            let receiver_initial_encrypted_balance =
                receiver_initial_balance.encrypt_with(receiver_pk);
            (
                receiver_sk,
                receiver_pk,
                *receiver_initial_balance,
                receiver_initial_encrypted_balance,
            )
        })
        .collect();
    let sender_final_balance = 10000u64;
    let transferred: u64 = transaction_values.iter().sum();
    let sender_initial_balance: u64 = sender_final_balance + transferred;
    let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(sender_pk);
    let transfers: Vec<(PublicKey, u64)> = receivers_info
        .iter()
        .map(|x| (x.1))
        .zip(transaction_values.clone())
        .collect();
    let transaction = Transaction::<u64>::create_transaction(
        &sender_initial_encrypted_balance,
        &transfers,
        None,
        sender_pk,
        &sender_sk,
    )
    .expect("Should be able to create transaction");

    assert!(transaction.verify_transaction().is_ok());
    assert_eq!(
        transaction
            .try_get_sender_final_balance(&sender_sk)
            .unwrap(),
        sender_final_balance
    );
    let receiver_final_encrypted_balances = transaction.get_receiver_final_encrypted_balance(
        &receivers_info.iter().map(|x| (x.3)).collect::<Vec<_>>(),
    );
    for (i, sk) in receivers_info.iter().map(|x| (&x.0)).enumerate() {
        // let start = Instant::now();
        // println!("准备解密");
        // println!("获取解密结果:{:?}",u64::try_decrypt_from(sk, receiver_final_encrypted_balances[i]).unwrap());
        // let elapsed = start.elapsed();
        // println!("用时{}秒",elapsed.as_secs());

        assert_eq!(
            receivers_info[i].2 + &transaction_values[i],
            u64::try_decrypt_from(sk, receiver_final_encrypted_balances[i]).unwrap()
        )
    }
}
