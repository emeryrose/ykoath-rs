/// Simple program for getting OATH/TOTP codes from a YubiKey and showing them
/// from a GTK application indicator for easy copying to clipboard.
extern crate gtk_sys;
extern crate gtk;
extern crate libappindicator;
extern crate notify_rust;
extern crate clipboard;
extern crate pcsc;

use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use notify_rust::Notification;
use gtk::prelude::*;
use gtk::{WidgetExt, MenuShellExt, MenuItemExt};
use libappindicator::{AppIndicator, AppIndicatorStatus};
use ykoath;

fn notify_code_copied() {
    let message = String::from("TOTP code copied to clipboard.");

    // Display the notification to the user
    Notification::new()
        .summary("YubiOATH")
        .body(&message)
        .icon("pgp-keys")
        .show().unwrap();
}

fn update_menu(indicator: &mut AppIndicator) -> gtk::Continue {
    // Create menu for listing the detected devices
    let mut menu = gtk::Menu::new();

    // Create a HID API context for detecting devices
    let context = pcsc::Context::establish(pcsc::Scope::User).unwrap();
 
    // List available readers
    let mut readers_buf = [0; 2048];
    let readers = context.list_readers(&mut readers_buf).unwrap();
    
    // Initialize a vector to track all our detected devices
    let mut yubikeys: Vec<ykoath::YubiKey> = Vec::new();

    // Iterate over the connected USB devices
    for reader in readers {
        yubikeys.push(ykoath::YubiKey{
            name: reader.to_str().unwrap(),
        });
    }
   
    // Show message if no YubiKey(s)
    if yubikeys.len() == 0 {
        let none_connected = gtk::MenuItem::new_with_label(
            "(No YubiKeys Detected)"
        );
        menu.append(&none_connected);
    }

    // Print device info for all the YubiKeys we detected
    for yubikey in yubikeys {
        // Create a menu item for the device
        let device_label: String = yubikey.name.to_owned();
        let device_entry = gtk::MenuItem::new_with_label(&device_label);
        let child_menu = gtk::Menu::new();
        let builder = gtk::Builder::new();
        let codes = match yubikey.get_oath_codes() {
            Ok(codes) => codes,
            Err(e) => {
                println!("ERROR {}", e);
                continue;
            },
        };
        
        // Show message is node codes found
        if codes.len() == 0 {
            let no_codes = gtk::MenuItem::new_with_label("(No Credentials)");
            child_menu.append(&no_codes);
        }

        // Enumerate the OATH codes and create a child menu for each device
        for oath in codes {
            let code = ykoath::format_code(oath.code.value, oath.code.digits);
            let name_clone = oath.name.clone();
            let mut label_vec: Vec<&str> = name_clone.split(":").collect();
            let mut code_entry_label: String = String::from(
                label_vec.remove(0)
            );
        
            if label_vec.len() > 0 {
                code_entry_label.push_str(" (");
                code_entry_label.push_str(&label_vec.join(""));
                code_entry_label.push_str(") ");
            }

            code_entry_label.push_str(&code.clone().to_owned());

            println!("DEBUG {}", code_entry_label);

            let code_entry = gtk::MenuItem::new_with_label(&code_entry_label);
            child_menu.append(&code_entry);

            // When the menu entry is clicked copy it to the clipboard and send
            // a desktop notification that we did so
            code_entry.connect_activate(move |_| {
                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                ctx.set_contents(code.clone()).unwrap();
                notify_code_copied();
            });
        }

        // Add the device to the menu
        device_entry.add_child(&builder, &child_menu, Some("submenu"));
        menu.append(&device_entry);
    }
   
    // Associate the menu with the app indicator and display it
    indicator.set_menu(&mut menu);
    menu.show_all();

    gtk::Continue(true)
}

fn main() {
    // Initialize GTK framework
    gtk::init().unwrap();

    // Create the indicator applet icon
    let mut indicator = AppIndicator::new("YubiOATH", "");
    
    // Set the status and the icon for the applet
    indicator.set_status(AppIndicatorStatus::APP_INDICATOR_STATUS_ACTIVE);
    indicator.set_icon_full("pgp-keys", "icon"); 

    // Update the menu entries
    update_menu(&mut indicator);
    
    // GTK is not thread safe and we can't Send between threads, so we are left 
    // with a long-polling style checking for new devices and TOTP codes
    gtk::timeout_add_seconds(10, move || {
        update_menu(&mut indicator)
    });

    // Run the main GTK loop
    gtk::main();
}
