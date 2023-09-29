/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.19",
  networks: {
    hardhat: {
        blockGasLimit: 100000000 // whatever you want here
    },
}
};
