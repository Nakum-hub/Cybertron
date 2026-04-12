import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Environment, Float, Lightformer } from '@react-three/drei';
import * as THREE from 'three';

function HexShield() {
  const groupRef = useRef<THREE.Group>(null);

  useFrame((state) => {
    if (!groupRef.current) return;
    groupRef.current.rotation.y = state.clock.elapsedTime * 0.12;
    groupRef.current.rotation.x = Math.sin(state.clock.elapsedTime * 0.2) * 0.04;
  });

  const hexPositions = useMemo(() => {
    const positions: [number, number, number][] = [];
    const rings = 3;
    for (let ring = 0; ring <= rings; ring++) {
      const count = ring === 0 ? 1 : ring * 6;
      for (let i = 0; i < count; i++) {
        const angle = (i / count) * Math.PI * 2;
        const r = ring * 0.55;
        positions.push([
          Math.cos(angle) * r,
          Math.sin(angle) * r,
          (Math.random() - 0.5) * 0.25,
        ]);
      }
    }
    return positions;
  }, []);

  return (
    <group ref={groupRef}>
      {hexPositions.map((pos, i) => (
        <mesh key={i} position={pos}>
          <cylinderGeometry args={[0.22, 0.22, 0.03, 6]} />
          <meshStandardMaterial
            color="#06b6d4"
            emissive="#0891b2"
            emissiveIntensity={0.3 + (i % 3) * 0.15}
            transparent
            opacity={0.25 + (i % 4) * 0.08}
            metalness={0.9}
            roughness={0.15}
          />
        </mesh>
      ))}
    </group>
  );
}

function CoreSphere() {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!meshRef.current) return;
    meshRef.current.rotation.y = state.clock.elapsedTime * 0.18;
    meshRef.current.rotation.z = state.clock.elapsedTime * 0.08;
    const pulse = 1 + Math.sin(state.clock.elapsedTime * 1.6) * 0.035;
    meshRef.current.scale.setScalar(pulse);
  });

  return (
    <Float speed={1.2} rotationIntensity={0.2} floatIntensity={0.4}>
      <mesh ref={meshRef}>
        <icosahedronGeometry args={[0.65, 4]} />
        <meshPhysicalMaterial
          color="#22d3ee"
          emissive="#0e7490"
          emissiveIntensity={0.5}
          transparent
          opacity={0.52}
          metalness={0.8}
          roughness={0.1}
          clearcoat={1}
          clearcoatRoughness={0.18}
          reflectivity={0.9}
        />
      </mesh>
    </Float>
  );
}

function OrbitRings() {
  const groupRef = useRef<THREE.Group>(null);

  useFrame((state) => {
    if (!groupRef.current) return;
    groupRef.current.rotation.y = state.clock.elapsedTime * 0.06;
  });

  return (
    <group ref={groupRef}>
      {[1.2, 1.6, 2.1].map((radius, i) => (
        <mesh key={i} rotation={[Math.PI / 2 + i * 0.15, i * 0.3, 0]}>
          <torusGeometry args={[radius, 0.006, 16, 100]} />
          <meshStandardMaterial
            color="#8b5cf6"
            emissive="#7c3aed"
            emissiveIntensity={0.4}
            transparent
            opacity={0.3 - i * 0.06}
          />
        </mesh>
      ))}
    </group>
  );
}

function DataNodes() {
  const nodesRef = useRef<THREE.Mesh[]>([]);

  const nodeData = useMemo(() => {
    const data: { position: [number, number, number]; speed: number; offset: number }[] = [];
    for (let i = 0; i < 14; i++) {
      const angle = (i / 14) * Math.PI * 2;
      const radius = 1.3 + Math.random() * 0.9;
      data.push({
        position: [
          Math.cos(angle) * radius,
          (Math.random() - 0.5) * 1.4,
          Math.sin(angle) * radius,
        ],
        speed: 0.4 + Math.random() * 1.2,
        offset: Math.random() * Math.PI * 2,
      });
    }
    return data;
  }, []);

  useFrame((state) => {
    nodesRef.current.forEach((node, i) => {
      if (!node) return;
      const d = nodeData[i];
      const t = state.clock.elapsedTime * d.speed + d.offset;
      node.position.y = d.position[1] + Math.sin(t) * 0.25;
      node.scale.setScalar(0.7 + Math.sin(t * 2) * 0.3);
    });
  });

  return (
    <group>
      {nodeData.map((d, i) => (
        <mesh
          key={i}
          ref={(el) => { if (el) nodesRef.current[i] = el; }}
          position={d.position}
        >
          <octahedronGeometry args={[0.05, 0]} />
          <meshStandardMaterial
            color="#22d3ee"
            emissive="#06b6d4"
            emissiveIntensity={1}
          />
        </mesh>
      ))}
    </group>
  );
}

function Scene() {
  return (
    <>
      <ambientLight intensity={0.2} />
      <pointLight position={[5, 4, 5]} intensity={0.6} color="#22d3ee" />
      <pointLight position={[-5, -3, 3]} intensity={0.3} color="#8b5cf6" />
      <pointLight position={[0, 3, -5]} intensity={0.2} color="#06b6d4" />
      <hemisphereLight intensity={0.25} color="#dbeafe" groundColor="#020617" />

      <CoreSphere />
      <HexShield />
      <OrbitRings />
      <DataNodes />

      <Environment resolution={128}>
        <Lightformer
          intensity={1.6}
          color="#22d3ee"
          position={[0, 2.5, -4]}
          rotation={[Math.PI / 2, 0, 0]}
          scale={[5.5, 1.25, 1]}
        />
        <Lightformer
          intensity={1.2}
          color="#7c3aed"
          position={[-3, 1, 2]}
          rotation={[0, Math.PI / 5, 0]}
          scale={[6, 2, 1]}
        />
        <Lightformer
          intensity={1}
          color="#0f172a"
          position={[0, -3, 0]}
          rotation={[Math.PI / 2, 0, 0]}
          scale={10}
        />
      </Environment>
    </>
  );
}

export default function CyberShieldScene({ className = '' }: { className?: string }) {
  return (
    <div className={className} style={{ width: '100%', height: '100%', pointerEvents: 'none' }}>
      <Canvas
        camera={{ position: [0, 0.3, 4.5], fov: 50 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent', pointerEvents: 'none' }}
        events={() => ({
          enabled: false,
          priority: 0,
          compute: () => {},
          connected: undefined,
          handlers: {} as any,
          update: () => {},
          connect: () => {},
          disconnect: () => {},
        })}
      >
        <Scene />
      </Canvas>
    </div>
  );
}
