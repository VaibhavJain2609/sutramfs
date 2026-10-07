import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The API routes shell out to sutramfsd (gRPC) and the sutramfs CLI.
  // Everything runs locally — no edge runtime, no external calls.
  serverExternalPackages: ["@grpc/grpc-js", "@grpc/proto-loader"],
};

export default nextConfig;
