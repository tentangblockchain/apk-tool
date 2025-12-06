const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class APKDiffAnalyzer {
  constructor() {
    this.originalDir = 'decompiled_original';
    this.modifiedDir = 'decompiled_modified';
    this.diffReport = {
      manifest_changes: [],
      smali_changes: [],
      vip_patterns: [],
      unlock_patterns: [],
      method_replacements: [],
      summary: {}
    };
  }

  async analyzeAPKs(originalApk, modifiedApk) {
    console.log('\n' + '='.repeat(70));
    console.log('🔍 APK DIFFERENTIAL ANALYSIS');
    console.log('='.repeat(70));
    
    console.log(`\n📦 Original APK: ${originalApk}`);
    console.log(`📦 Modified APK: ${modifiedApk}`);

    // Decompile both
    await this.decompileAPK(originalApk, this.originalDir);
    await this.decompileAPK(modifiedApk, this.modifiedDir);

    // Analyze differences
    this.analyzeManifestDiff();
    this.analyzeSmaliDiff();
    
    this.printReport();
    this.saveReport();
  }

  async decompileAPK(apkPath, outputDir) {
    if (!fs.existsSync(apkPath)) {
      console.error(`❌ APK not found: ${apkPath}`);
      return;
    }

    console.log(`\n🔓 Decompiling to ${outputDir}...`);
    
    if (fs.existsSync(outputDir)) {
      execSync(`rm -rf ${outputDir}`);
    }

    try {
      execSync(`java -Xmx2048m -jar apktool.jar d "${apkPath}" -o ${outputDir} -f`, {
        stdio: 'inherit',
        timeout: 600000
      });
      console.log(`✅ Decompiled to ${outputDir}`);
    } catch (e) {
      console.error(`❌ Failed to decompile: ${e.message}`);
      throw e;
    }
  }

  analyzeManifestDiff() {
    console.log('\n📋 Analyzing AndroidManifest.xml changes...');
    
    const origManifest = fs.readFileSync(
      path.join(this.originalDir, 'AndroidManifest.xml'), 
      'utf8'
    );
    const modManifest = fs.readFileSync(
      path.join(this.modifiedDir, 'AndroidManifest.xml'), 
      'utf8'
    );

    // Find permission changes
    const origPerms = [...origManifest.matchAll(/android:name="(android\.permission\.\w+)"/g)];
    const modPerms = [...modManifest.matchAll(/android:name="(android\.permission\.\w+)"/g)];

    const origPermSet = new Set(origPerms.map(m => m[1]));
    const modPermSet = new Set(modPerms.map(m => m[1]));

    const added = [...modPermSet].filter(p => !origPermSet.has(p));
    const removed = [...origPermSet].filter(p => !modPermSet.has(p));

    if (added.length > 0) {
      console.log(`   ✅ Added permissions: ${added.join(', ')}`);
      this.diffReport.manifest_changes.push({ type: 'permission_added', permissions: added });
    }
    if (removed.length > 0) {
      console.log(`   ✅ Removed permissions: ${removed.join(', ')}`);
      this.diffReport.manifest_changes.push({ type: 'permission_removed', permissions: removed });
    }
  }

  analyzeSmaliDiff() {
    console.log('\n🔍 Scanning for Smali file changes...');

    const origSmaliDirs = this.getAllSmaliDirs(this.originalDir);
    const modSmaliDirs = this.getAllSmaliDirs(this.modifiedDir);

    let filesChanged = 0;
    let filesAnalyzed = 0;

    // Compare each file
    for (const dir of modSmaliDirs) {
      const modDir = path.join(this.modifiedDir, dir);
      const origDir = path.join(this.originalDir, dir);

      if (!fs.existsSync(modDir)) continue;

      this.walkDirectory(modDir, (filePath) => {
        if (!filePath.endsWith('.smali')) return;

        filesAnalyzed++;
        const relPath = filePath.replace(modDir, '');
        const origPath = path.join(origDir, relPath);

        if (!fs.existsSync(origPath)) {
          console.log(`   ℹ️  New file: ${relPath}`);
          return;
        }

        const origContent = fs.readFileSync(origPath, 'utf8');
        const modContent = fs.readFileSync(filePath, 'utf8');

        if (origContent !== modContent) {
          filesChanged++;
          this.analyzeMethodChanges(origPath, filePath, relPath);
        }
      });
    }

    console.log(`\n   📊 Files analyzed: ${filesAnalyzed}`);
    console.log(`   ✏️  Files modified: ${filesChanged}`);

    this.diffReport.summary.files_changed = filesChanged;
    this.diffReport.summary.files_analyzed = filesAnalyzed;
  }

  analyzeMethodChanges(origPath, modPath, relPath) {
    const origContent = fs.readFileSync(origPath, 'utf8');
    const modContent = fs.readFileSync(modPath, 'utf8');

    // Find method bodies that changed
    const methodPattern = /\.method\s+([^(]+)\([^)]*\)([^}\n]+)[^\n]*\n([\s\S]*?)\.end method/g;

    let origMethods = new Map();
    let modMethods = new Map();

    let match;
    while ((match = methodPattern.exec(origContent)) !== null) {
      const key = match[1].trim() + match[2].trim();
      origMethods.set(key, match[3]);
    }

    methodPattern.lastIndex = 0;
    while ((match = methodPattern.exec(modContent)) !== null) {
      const key = match[1].trim() + match[2].trim();
      modMethods.set(key, match[3]);
    }

    // Find changed methods
    for (const [key, modBody] of modMethods) {
      const origBody = origMethods.get(key);
      if (origBody && origBody !== modBody) {
        const methodName = key.split(/\s+/)[0];
        
        // Analyze the modification
        if (modBody.includes('const/4 v0, 0x1') || modBody.includes('const/4 v0, 0x0')) {
          // Boolean return modification
          const returnVal = modBody.includes('0x1') ? 'true' : 'false';
          
          if (methodName.includes('isVip') || methodName.includes('isPremium')) {
            console.log(`   🎯 VIP Bypass: ${methodName} → return ${returnVal}`);
            this.diffReport.vip_patterns.push({
              file: relPath,
              method: methodName,
              original_body: origBody.substring(0, 100),
              new_body: modBody.substring(0, 100),
              pattern: 'const/4 return'
            });
          } else if (methodName.includes('isLock') || methodName.includes('unlock')) {
            console.log(`   🎯 Unlock: ${methodName} → return ${returnVal}`);
            this.diffReport.unlock_patterns.push({
              file: relPath,
              method: methodName,
              pattern: 'const/4 return'
            });
          }
        }

        // Check for permission modifications
        if (relPath.includes('Manifest')) {
          console.log(`   🎯 Manifest change: ${methodName}`);
        }

        this.diffReport.method_replacements.push({
          file: relPath,
          method: methodName,
          original_size: origBody.length,
          modified_size: modBody.length,
          size_diff: modBody.length - origBody.length
        });
      }
    }
  }

  getAllSmaliDirs(baseDir) {
    const dirs = [];
    try {
      const items = fs.readdirSync(baseDir);
      for (const item of items) {
        if (item.startsWith('smali')) {
          dirs.push(item);
        }
      }
    } catch (e) {
      // ignore
    }
    return dirs;
  }

  walkDirectory(dir, callback) {
    try {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          this.walkDirectory(fullPath, callback);
        } else {
          callback(fullPath);
        }
      }
    } catch (e) {
      // ignore
    }
  }

  printReport() {
    console.log('\n' + '='.repeat(70));
    console.log('📊 DIFFERENTIAL ANALYSIS REPORT');
    console.log('='.repeat(70));

    if (this.diffReport.manifest_changes.length > 0) {
      console.log('\n🔐 Manifest Changes:');
      for (const change of this.diffReport.manifest_changes) {
        if (change.type === 'permission_added') {
          console.log(`   ✅ Added: ${change.permissions.join(', ')}`);
        } else {
          console.log(`   ❌ Removed: ${change.permissions.join(', ')}`);
        }
      }
    }

    if (this.diffReport.vip_patterns.length > 0) {
      console.log(`\n💎 VIP Bypass Patterns Found: ${this.diffReport.vip_patterns.length}`);
      for (const pattern of this.diffReport.vip_patterns.slice(0, 5)) {
        console.log(`   • ${pattern.file}`);
        console.log(`     Method: ${pattern.method}`);
        console.log(`     Pattern: ${pattern.pattern}`);
      }
    }

    if (this.diffReport.unlock_patterns.length > 0) {
      console.log(`\n🎬 Unlock Patterns Found: ${this.diffReport.unlock_patterns.length}`);
      for (const pattern of this.diffReport.unlock_patterns.slice(0, 5)) {
        console.log(`   • ${pattern.file}`);
        console.log(`     Method: ${pattern.method}`);
      }
    }

    console.log(`\n📈 Summary:`);
    console.log(`   Files analyzed: ${this.diffReport.summary.files_analyzed}`);
    console.log(`   Files changed: ${this.diffReport.summary.files_changed}`);
    console.log(`   Method replacements: ${this.diffReport.method_replacements.length}`);
  }

  saveReport() {
    const reportPath = 'diff-analysis-report.json';
    fs.writeFileSync(reportPath, JSON.stringify(this.diffReport, null, 2));
    console.log(`\n📄 Report saved to: ${reportPath}`);
  }
}

// Main
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length < 2) {
    console.log('\n📖 Usage: node apk-diff-analyzer.js <original.apk> <modified.apk>');
    console.log('\nExample:');
    console.log('  node apk-diff-analyzer.js apk/base.apk final-signed.apk');
    process.exit(1);
  }

  const analyzer = new APKDiffAnalyzer();
  await analyzer.analyzeAPKs(args[0], args[1]);
}

main().catch(console.error);
