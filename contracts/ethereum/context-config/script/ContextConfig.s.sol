// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {ContextConfig} from "../src/ContextConfig.sol";

contract ContextConfigScript is Script {
    ContextConfig public config;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy with just the owner address
        config = new ContextConfig(0x50B69dE34fA8326AcD9853c847CA9365e341D636);

        vm.stopBroadcast();
    }
}
