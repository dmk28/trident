mod domain_resolver;
mod os_fingerprint;

use os_fingerprint::{test_businesscorp_focused, test_comprehensive_service_detection};

#[tokio::main]
async fn main() {
    println!("🚀 Project Trident - Comprehensive Service Detection Test\n");

    // Run the comprehensive multi-target test
    test_comprehensive_service_detection().await;

    println!("\n{}", "=".repeat(70));
    println!("🎯 FOCUSED EDUCATIONAL TARGET TEST");
    println!("{}", "=".repeat(70));
    println!();

    // Run focused test on DESEC training target
    test_businesscorp_focused().await;

    println!("\n🎉 Service detection testing complete!");
    println!("💡 Your scanner can now automatically identify services!");
}
