import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Deploy the trust layer and register the six agent identities.
 *
 *   npx hardhat run scripts/deploy.ts --network localhost
 *   npx hardhat run scripts/deploy.ts --network sepolia
 *
 * Writes addresses and ABIs to ../artifacts/chain/deployment.json, which is what the Python
 * client reads. Nothing is hard-coded on either side.
 *
 * Agent addresses are derived deterministically from the deployer key, so the same deployer
 * always produces the same six identities and a redeploy does not invalidate anything recorded
 * off-chain about which address held which role.
 */

const AGENT_ROLES = [
  "detection",
  "correlation",
  "investigation",
  "triage",
  "remediation",
  "verifier",
] as const;

/** Enough for a handful of submissions on a testnet; the deployer keeps the rest. */
const AGENT_FUNDING = ethers.parseEther("0.005");

function deriveAgentWallets(seed: string, count: number) {
  // Deterministic derivation from the deployer key. These are throwaway identities whose only
  // authority is what the registry grants them, and whose only funds are gas.
  return Array.from({ length: count }, (_, i) => {
    const key = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "string", "uint256"], [seed, "agentsphere-agent", i])
    );
    return new ethers.Wallet(key, ethers.provider);
  });
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`network   ${network.name} (chainId ${network.config.chainId})`);
  console.log(`deployer  ${deployer.address}`);
  console.log(`balance   ${ethers.formatEther(balance)} ETH\n`);

  if (balance === 0n) {
    throw new Error(
      `Deployer ${deployer.address} has no funds. Fund it from a faucet and re-run.`
    );
  }

  const registry = await (await ethers.getContractFactory("AgentRegistry")).deploy();
  await registry.waitForDeployment();
  const registryAddress = await registry.getAddress();
  console.log(`AgentRegistry  ${registryAddress}`);

  const proof = await (
    await ethers.getContractFactory("DecisionProof")
  ).deploy(registryAddress);
  await proof.waitForDeployment();
  const proofAddress = await proof.getAddress();
  console.log(`DecisionProof  ${proofAddress}\n`);

  // Seed the derivation from the deployer address so local and testnet runs stay distinct.
  const seed = ethers.keccak256(ethers.toUtf8Bytes(deployer.address));
  const wallets = deriveAgentWallets(seed, AGENT_ROLES.length);

  const agents: Record<string, string> = {};
  for (let i = 0; i < AGENT_ROLES.length; i++) {
    const role = AGENT_ROLES[i];
    const wallet = wallets[i];
    const metadataHash = ethers.keccak256(ethers.toUtf8Bytes(`agentsphere:${role}:v1`));
    await (await registry.registerAgent(wallet.address, role, metadataHash)).wait();
    agents[role] = wallet.address;
    console.log(`  registered ${role.padEnd(14)} ${wallet.address}`);
  }

  // Only the agents that actually send transactions need gas. Fund them from the deployer so a
  // human has to visit a faucet exactly once.
  const funded: string[] = [];
  for (const role of ["triage", "verifier"] as const) {
    const target = agents[role];
    if ((await ethers.provider.getBalance(target)) < AGENT_FUNDING) {
      await (await deployer.sendTransaction({ to: target, value: AGENT_FUNDING })).wait();
      funded.push(role);
    }
  }
  if (funded.length) console.log(`\n  funded for gas: ${funded.join(", ")}`);

  // A deliberately unregistered address, so the "unauthorised agent is rejected" demo has a
  // real actor to attempt it.
  const rogue = new ethers.Wallet(
    ethers.keccak256(ethers.toUtf8Bytes(`${seed}:rogue`)),
    ethers.provider
  );

  const deployment = {
    network: network.name,
    chainId: Number(network.config.chainId),
    deployedAt: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      AgentRegistry: {
        address: registryAddress,
        abi: JSON.parse(
          (await ethers.getContractFactory("AgentRegistry")).interface.formatJson()
        ),
      },
      DecisionProof: {
        address: proofAddress,
        abi: JSON.parse(
          (await ethers.getContractFactory("DecisionProof")).interface.formatJson()
        ),
      },
    },
    agents,
    agentKeys: Object.fromEntries(
      AGENT_ROLES.map((role, i) => [role, wallets[i].privateKey])
    ),
    rogue: { address: rogue.address, privateKey: rogue.privateKey },
  };

  const out = path.resolve(__dirname, "..", "..", "artifacts", "chain");
  fs.mkdirSync(out, { recursive: true });
  const file = path.join(out, `deployment.${network.name}.json`);
  fs.writeFileSync(file, JSON.stringify(deployment, null, 2));
  // Also write the unsuffixed name the Python client loads by default.
  fs.writeFileSync(path.join(out, "deployment.json"), JSON.stringify(deployment, null, 2));

  console.log(`\ndeployment -> ${file}`);
  if (network.name === "sepolia") {
    console.log(`\nexplorer:`);
    console.log(`  https://sepolia.etherscan.io/address/${registryAddress}`);
    console.log(`  https://sepolia.etherscan.io/address/${proofAddress}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
