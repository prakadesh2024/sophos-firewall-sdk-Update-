import os
import traceback
from sophosfirewall_python.firewallapi import SophosFirewall
from sophosfirewall_python.api_client import SophosFirewallAPIError


def run_cleanup():
    """Run only the cleanup function without stopping if items don't exist, 
    and print all failures at the end."""
    fw = SophosFirewall(
        username=os.environ["XG_USERNAME"],
        password=os.environ["XG_PASSWORD"],
        hostname=os.environ["XG_HOSTNAME"],
        port=4444,
        verify=False,
    )

    errors = []  # collect all error messages and stack traces

    def remove(tag, name, key=None):
        try:
            if key:
                fw.remove(xml_tag=tag, name=name, key=key)
            else:
                fw.remove(xml_tag=tag, name=name)
            print(f"Removed {tag} {name}")
        except SophosFirewallAPIError:
            print(f"{tag} {name} not found — skipping")
        except Exception as e:
            print(f"Error removing {tag} {name} — will report at end")
            errors.append(traceback.format_exc())

    print("\nRunning cleanup...")

    try:
        fw.update_acl_rule(
            name="FUNC_SVCACL",
            source_list=["FUNC_TESTHOST1"],
            update_action="remove",
        )
        print("Removed FUNC_TESTHOST1 from LocalServiceACL")
    except Exception:
        print("FUNC_TESTHOST1 not found in LocalServiceACL — skipping")
        errors.append(traceback.format_exc())

    remove("LocalServiceACL", "FUNC_SVCACL", key="RuleName")
    remove("FirewallRule", "FUNC_TESTRULE1")
    remove("IPHost", "FUNC_TESTNETWORK2")
    remove("IPHost", "FUNC_TESTNETWORK1")
    remove("IPHost", "FUNC_TESTHOST1_IPLIST")
    remove("IPHostGroup", "FUNC_TESTGROUP1")
    remove("FQDNHostGroup", "FUNC_TESTFQDNGROUP1")
    remove("IPHost", "FUNC_TESTHOST1")
    remove("IPHost", "FUNC_TESTHOST2")
    remove("FQDNHost", "FUNC_TESTFQDNHOST1")
    remove("FQDNHost", "FUNC_TESTFQDNHOST2")
    remove("ServiceGroup", "FUNC_TESTSVCGROUP1")
    remove("Services", "FUNC_TESTSVC1")
    remove("Services", "FUNC_TESTSVC2")
    remove("WebFilterURLGroup", "FUNC_URLGROUP1")
    remove("User", "func_testuser1")

    # Print collected errors at the end
    if errors:
        print("\n=== Cleanup completed with errors ===")
        for i, err in enumerate(errors, start=1):
            print(f"\n--- Error {i} ---")
            print(err)
    else:
        print("\nCleanup completed without errors.")


if __name__ == "__main__":
    run_cleanup()
