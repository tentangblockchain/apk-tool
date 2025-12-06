
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const readline = require('readline');

// ============================================================================
// CLASS: ToolBuilder
// ============================================================================
class ToolBuilder {
  static async setupTools() {
    console.log('📦 Preparing APK tools...\n');

    try {
      // Check if tools already exist
      if (fs.existsSync('apktool.jar') && fs.existsSync('jadx/bin/jadx')) {
        console.log('✅ Tools already installed\n');
        return true;
      }

      // Download apktool
      if (!fs.existsSync('apktool.jar')) {
        console.log('⬇️  Downloading apktool...');
        execSync('wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar -O apktool.jar');
        console.log('✅ apktool downloaded');
      }

      // Download and setup jadx
      if (!fs.existsSync('jadx/bin/jadx')) {
        console.log('⬇️  Downloading jadx...');
        execSync('wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip');
        execSync('unzip -q jadx-1.4.7.zip -d jadx');
        execSync('chmod +x jadx/bin/jadx');
        console.log('✅ jadx downloaded and extracted');
      }

      console.log('\n✅ All tools ready!\n');
      return true;
    } catch (error) {
      console.error('❌ Tool setup failed:', error.message);
      return false;
    }
  }
}

// ============================================================================
// CLASS: APKSelector
// ============================================================================
class APKSelector {
  constructor() {
    this.apkDir = 'apk';
  }

  // Get all APK files
  getAvailableAPKs() {
    if (!fs.existsSync(this.apkDir)) {
      console.log(`⚠️  Directory not found: ${this.apkDir}`);
      return [];
    }

    const files = fs.readdirSync(this.apkDir);
    return files.filter(file => file.toLowerCase().endsWith('.apk'))
      .map(file => ({
        name: file,
        path: path.join(this.apkDir, file),
        size: fs.statSync(path.join(this.apkDir, file)).size
      }));
  }

  // Format file size
  formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
  }

  // Display available APKs
  displayAPKs() {
    const apks = this.getAvailableAPKs();

    if (apks.length === 0) {
      console.log('\n❌ No APK files found in apk/ directory');
      return null;
    }

    console.log('\n📦 Available APK files:\n');
    apks.forEach((apk, index) => {
      console.log(`${index + 1}. ${apk.name}`);
      console.log(`   📊 Size: ${this.formatSize(apk.size)}`);
      console.log(`   📍 Path: ${apk.path}\n`);
    });

    return apks;
  }

  // Interactive selection
  async selectAPKInteractive() {
    const apks = this.displayAPKs();

    if (!apks || apks.length === 0) {
      return null;
    }

    if (apks.length === 1) {
      console.log('✅ Only one APK found, selecting automatically...\n');
      return apks[0];
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    return new Promise((resolve) => {
      rl.question('Enter number to select APK (1-' + apks.length + '): ', (answer) => {
        rl.close();
        
        const index = parseInt(answer) - 1;
        if (index >= 0 && index < apks.length) {
          console.log(`\n✅ Selected: ${apks[index].name}\n`);
          resolve(apks[index]);
        } else {
          console.log('\n❌ Invalid selection');
          resolve(null);
        }
      });
    });
  }

  // Get APK by name pattern
  findAPKByPattern(pattern) {
    const apks = this.getAvailableAPKs();
    
    const found = apks.find(apk => 
      apk.name.toLowerCase().includes(pattern.toLowerCase())
    );

    if (found) {
      console.log(`✅ Found APK: ${found.name}`);
      return found;
    }

    console.log(`❌ APK matching "${pattern}" not found`);
    return null;
  }
}

// ============================================================================
// CLASS: APKAnalyzer
// ============================================================================
class APKAnalyzer {
  constructor(apkPath) {
    this.apkPath = apkPath;
    this.outputDir = 'decompiled';
    this.analysis = {
      packageName: null,
      appName: null,
      version: null,
      permissions: [],
      activities: [],
      services: [],
      vipPatterns: [],
      episodePatterns: [],
      loginPatterns: [],
      vpnBlockPatterns: [],
      stringResources: {}
    };
  }

  // Parse AndroidManifest.xml
  analyzeManifest() {
    console.log('\n📋 Analyzing AndroidManifest.xml...');

    const manifestPath = path.join(this.outputDir, 'AndroidManifest.xml');

    if (!fs.existsSync(manifestPath)) {
      console.log('⚠️  AndroidManifest.xml not found');
      return;
    }

    try {
      const content = fs.readFileSync(manifestPath, 'utf8');

      // Extract package name
      const pkgMatch = content.match(/package="([^"]+)"/);
      if (pkgMatch) {
        this.analysis.packageName = pkgMatch[1];
        console.log(`✅ Package: ${this.analysis.packageName}`);
      }

      // Extract version
      const verMatch = content.match(/android:versionName="([^"]+)"/);
      if (verMatch) {
        this.analysis.version = verMatch[1];
        console.log(`✅ Version: ${this.analysis.version}`);
      }

      // Extract permissions
      const permMatches = content.matchAll(/android:name="([^"]+)"/g);
      for (const match of permMatches) {
        if (match[1].startsWith('android.permission.')) {
          this.analysis.permissions.push(match[1]);
        }
      }
      console.log(`✅ Found ${this.analysis.permissions.length} permissions`);

      // Extract activities
      const activityMatches = content.matchAll(/<activity\s+android:name="([^"]+)"/g);
      for (const match of activityMatches) {
        this.analysis.activities.push(match[1]);
      }
      console.log(`✅ Found ${this.analysis.activities.length} activities`);

      // Extract services
      const serviceMatches = content.matchAll(/<service\s+android:name="([^"]+)"/g);
      for (const match of serviceMatches) {
        this.analysis.services.push(match[1]);
      }
      console.log(`✅ Found ${this.analysis.services.length} services`);
    } catch (e) {
      console.log('⚠️  Error parsing manifest:', e.message);
    }
  }

  // Analyze strings.xml
  analyzeStrings() {
    console.log('\n📝 Analyzing strings.xml...');

    const stringsPath = path.join(this.outputDir, 'res', 'values', 'strings.xml');

    if (!fs.existsSync(stringsPath)) {
      console.log('⚠️  strings.xml not found');
      return;
    }

    try {
      const content = fs.readFileSync(stringsPath, 'utf8');

      // Extract all string resources
      const stringMatches = content.matchAll(/<string\s+name="([^"]+)">([^<]+)<\/string>/g);
      for (const match of stringMatches) {
        this.analysis.stringResources[match[1]] = match[2];
      }

      console.log(`✅ Found ${Object.keys(this.analysis.stringResources).length} strings`);

      // Look for VIP-related strings
      Object.entries(this.analysis.stringResources).forEach(([key, value]) => {
        if (value.toLowerCase().includes('vip') || 
            value.toLowerCase().includes('premium') ||
            value.toLowerCase().includes('pro')) {
          this.analysis.vipPatterns.push({ key, value });
        }
      });

      if (this.analysis.vipPatterns.length > 0) {
        console.log(`🔍 Found ${this.analysis.vipPatterns.length} VIP-related strings`);
      }
    } catch (e) {
      console.log('⚠️  Error analyzing strings:', e.message);
    }
  }

  // Analyze smali files for key patterns
  analyzeSmaliPatterns() {
    console.log('\n🔍 Analyzing Smali code patterns...');

    const smaliDir = path.join(this.outputDir, 'smali');

    if (!fs.existsSync(smaliDir)) {
      console.log('⚠️  Smali directory not found');
      return;
    }

    try {
      let smaliCount = 0;
      let vipFound = 0;
      let episodeFound = 0;
      let loginFound = 0;
      let vpnFound = 0;

      const walkDir = (dir) => {
        try {
          const files = fs.readdirSync(dir);

          for (const file of files) {
            try {
              const fullPath = path.join(dir, file);
              const stat = fs.statSync(fullPath);

              if (stat.isDirectory()) {
                walkDir(fullPath);
              } else if (file.endsWith('.smali')) {
                smaliCount++;

                try {
                  const content = fs.readFileSync(fullPath, 'utf8');

                  // Check for VIP patterns
                  if (content.match(/isPremium|isVIP|hasPremium|vipCheck|premiumCheck/i)) {
                    vipFound++;
                  }

                  // Check for Episode patterns
                  if (content.match(/unlock|episode|locked|isLocked/i) ||
                      fullPath.includes('RequestApiLib') ||
                      fullPath.includes('AlbumVM')) {
                    episodeFound++;
                    this.analysis.episodePatterns.push(fullPath);
                  }

                  // Check for Login patterns
                  if (content.match(/isLoggedIn|checkLogin|requireLogin|auth|Auth|login/i) ||
                      fullPath.includes('RequestApiLib') ||
                      fullPath.includes('MainActivity') ||
                      fullPath.includes('Authentication')) {
                    loginFound++;
                    this.analysis.loginPatterns.push(fullPath);
                  }

                  // Check for VPN block patterns
                  if (content.match(/VPN|vpn|proxy|Proxy|checkVPN|isVPN/i)) {
                    vpnFound++;
                    this.analysis.vpnBlockPatterns.push(fullPath);
                  }
                } catch (e) {
                  // Skip if can't read
                }
              }
            } catch (e) {
              // Skip inaccessible files
            }
          }
        } catch (e) {
          // Skip inaccessible dirs
        }
      };

      walkDir(smaliDir);

      console.log(`✅ Scanned ${smaliCount} Smali files`);
      console.log(`   🔸 VIP methods: ${vipFound}`);
      console.log(`   🔸 Episode files: ${episodeFound}`);
      console.log(`   🔸 Login methods: ${loginFound}`);
      console.log(`   🔸 VPN blocks: ${vpnFound}`);
    } catch (e) {
      console.log('⚠️  Error analyzing smali:', e.message);
    }
  }

  // Full analysis
  async analyze() {
    console.log('\n🚀 Starting APK Analysis...');
    console.log(`📦 APK: ${this.apkPath}\n`);

    if (!fs.existsSync(this.apkPath)) {
      console.error(`❌ APK not found: ${this.apkPath}`);
      return null;
    }

    // Decompile first with optimized settings for large APKs
    try {
      console.log('🔓 Decompiling APK (this may take a few minutes for large files)...');

      // Use increased heap and only-main-classes for large APKs
      const decompileCmd = `java -Xmx2048m -jar apktool.jar d "${this.apkPath}" -o ${this.outputDir} -f`;

      execSync(decompileCmd, { 
        timeout: 600000, // 10 minutes
        maxBuffer: 200 * 1024 * 1024,
        stdio: 'inherit'
      });
      console.log('✅ Decompiled');
    } catch (e) {
      console.error('❌ Decompile failed, trying without resources...');

      // Fallback: try without resources
      try {
        const fallbackCmd = `java -Xmx2048m -jar apktool.jar d "${this.apkPath}" -o ${this.outputDir} -f -r`;
        execSync(fallbackCmd, { 
          timeout: 600000,
          maxBuffer: 50 * 1024 * 1024,
          stdio: 'inherit'
        });
        console.log('✅ Decompiled (without resources)');
      } catch (e2) {
        console.error('❌ Decompile completely failed:', e2.message);
        return null;
      }
    }

    // Run analysis
    this.analyzeManifest();
    this.analyzeStrings();
    this.analyzeSmaliPatterns();

    console.log('\n📊 Analysis Complete!');
    return this.analysis;
  }

  // Save analysis report
  saveReport(reportPath = 'analysis.json') {
    try {
      fs.writeFileSync(reportPath, JSON.stringify(this.analysis, null, 2));
      console.log(`📄 Report saved to: ${reportPath}`);
    } catch (e) {
      console.log('⚠️  Could not save report:', e.message);
    }
  }

  // Print summary
  printSummary() {
    console.log('\n' + '='.repeat(60));
    console.log('📋 APK ANALYSIS SUMMARY');
    console.log('='.repeat(60));
    console.log(`Package: ${this.analysis.packageName}`);
    console.log(`Version: ${this.analysis.version}`);
    console.log(`Permissions: ${this.analysis.permissions.length}`);
    console.log(`Activities: ${this.analysis.activities.length}`);
    console.log(`Services: ${this.analysis.services.length}`);
    console.log(`\n🔍 Detected Patterns:`);
    console.log(`   VIP: ${this.analysis.vipPatterns.length} strings`);
    console.log(`   Episodes: ${this.analysis.episodePatterns.length} files`);
    console.log(`   Login: ${this.analysis.loginPatterns.length} files`);
    console.log(`   VPN: ${this.analysis.vpnBlockPatterns.length} files`);
    console.log('='.repeat(60));
  }
}

// ============================================================================
// CLASS: APKModifier
// ============================================================================
class APKModifier {
  constructor(apkPath, analysis) {
    this.apkPath = apkPath;
    this.outputDir = 'decompiled';
    this.modifiedApk = 'modified.apk';
    this.analysis = analysis;
    this.modifications = {
      applied: 0,
      failed: 0,
      skipped: 0
    };
    
    // Auto-detect app package dari analysis
    this.appPackages = this.detectAppPackages();
    
    console.log(`\n🎯 Detected app packages: ${this.appPackages.join(', ')}`);
    
    // Libraries yang TIDAK BOLEH dimodifikasi
    this.excludePackages = [
      'androidx/',
      'android/',
      'com/google/',
      'com/facebook/',
      'com/explorestack/',
      'com/mbridge/',
      'com/unity3d/',
      'com/vungle/',
      'com/sobot/',
      'com/sensorsdata/',
      'io/bidmachine/',
      'kotlin/',
      'kotlinx/',
      'okhttp3/',
      'retrofit2/',
      'com/bytedance/',
      'com/bytedance/bdtracker/'
    ];
  }
  
  // Detect app packages from package name
  detectAppPackages() {
    const packages = [];
    
    if (this.analysis && this.analysis.packageName) {
      const mainPkg = this.analysis.packageName.replace(/\./g, '/');
      packages.push(mainPkg);
      
      // Check for common sub-packages
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
      
      for (const dir of smaliDirs) {
        if (fs.existsSync(dir)) {
          const mainPath = path.join(dir, mainPkg);
          if (fs.existsSync(mainPath)) {
            try {
              const subDirs = fs.readdirSync(mainPath);
              for (const sub of subDirs) {
                const subPath = path.join(mainPath, sub);
                if (fs.statSync(subPath).isDirectory()) {
                  packages.push(`${mainPkg}/${sub}`);
                }
              }
            } catch (e) {
              // Skip
            }
          }
        }
      }
    }
    
    // Fallback if no packages detected
    if (packages.length === 0) {
      packages.push('com/storymatrix/drama');
    }
    
    return packages;
  }

  // Check apakah file ini boleh dimodifikasi (EXPANDED for VIP/Episode bypass)
  isModifiableFile(filePath, aggressiveMode = false) {
    // Aggressive mode: allow modifying relevant libraries
    if (aggressiveMode) {
      // ALLOW certain libraries that might contain VIP/episode logic
      const allowedLibs = [
        'com/bytedance/sdk/openadsdk/',  // ByteDance ad SDK - might handle paywall
        'com/applovin/',                 // AppLovin - monetization
        'com/facebook/ads/',             // Facebook ads
        // Add any custom monetization libraries
      ];
      
      for (const lib of allowedLibs) {
        if (filePath.includes(lib)) {
          return true;
        }
      }
    }
    
    // Check apakah termasuk dalam excluded packages (strict mode)
    for (const excluded of this.excludePackages) {
      if (filePath.includes(excluded)) {
        return false;
      }
    }
    
    // Check apakah termasuk dalam app packages
    for (const appPkg of this.appPackages) {
      if (filePath.includes(appPkg)) {
        return true;
      }
    }
    
    return false;
  }

  // Edit file safely
  editFile(filePath, searchText, replaceText) {
    try {
      if (!fs.existsSync(filePath)) {
        return false;
      }

      let content = fs.readFileSync(filePath, 'utf8');
      const originalContent = content;
      
      if (content.includes(searchText)) {
        content = content.split(searchText).join(replaceText);
      } else {
        try {
          content = content.replace(new RegExp(searchText, 'g'), replaceText);
        } catch (e) {
          return false;
        }
      }
      
      if (content !== originalContent) {
        fs.writeFileSync(filePath, content, 'utf8');
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  // Safe directory walker
  walkDirectory(dir, callback) {
    try {
      const files = fs.readdirSync(dir);
      
      for (const file of files) {
        try {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          
          if (stat.isDirectory()) {
            this.walkDirectory(fullPath, callback);
          } else {
            callback(fullPath, file);
          }
        } catch (e) {
          // Skip
        }
      }
    } catch (e) {
      // Skip
    }
  }

  // === FITUR MODIFICATIONS ===

  // 1. Fixed Screen Off - Add WAKE_LOCK permission
  async fixScreenOff() {
    console.log('\n🔆 [1/8] Fixed Screen Off');
    
    const manifestPath = path.join(this.outputDir, 'AndroidManifest.xml');
    
    try {
      if (!fs.existsSync(manifestPath)) {
        console.log('   ⚠️  Manifest not found');
        this.modifications.skipped++;
        return;
      }

      let content = fs.readFileSync(manifestPath, 'utf8');
      
      if (!content.includes('android.permission.WAKE_LOCK')) {
        const insertPos = content.indexOf('<application');
        if (insertPos > 0) {
          content = content.slice(0, insertPos) + 
            '<uses-permission android:name="android.permission.WAKE_LOCK" />\n    ' +
            content.slice(insertPos);
          
          fs.writeFileSync(manifestPath, content, 'utf8');
          console.log('   ✅ WAKE_LOCK permission added');
          this.modifications.applied++;
          return;
        }
      }
      
      console.log('   ⚠️  Already present');
      this.modifications.skipped++;
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // Helper: Replace entire method body safely (prevents dead code crashes)
  replaceMethodBody(content, methodSignatureRegex, newBodyCode) {
    return content.replace(methodSignatureRegex, (fullMatch) => {
      // Extract method signature (everything before .locals or first instruction)
      const signatureMatch = fullMatch.match(/^(\.method[^\n]*\n(?:\s*\.(?:annotation|param)[^\n]*\n)*)/);
      if (!signatureMatch) return fullMatch;
      
      const signature = signatureMatch[1];
      
      // Extract .locals directive
      const localsMatch = fullMatch.match(/\.locals\s+(\d+)/);
      const localsCount = localsMatch ? Math.max(parseInt(localsMatch[1]), 1) : 1;
      
      // Build clean method with ONLY the new body (no dead code)
      const cleanMethod = `${signature}    .locals ${localsCount}\n\n${newBodyCode}\n.end method`;
      
      return cleanMethod;
    });
  }

  // 2. VIP Bypass - SAFE version with full method body replacement
  async bypassVIP() {
    console.log('\n💎 [2/8] VIP Bypass (Safe Edition)');
    
    try {
      let modified = 0;
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3', 
                         'decompiled/smali_classes4', 'decompiled/smali_classes5', 'decompiled/smali_classes6', 'decompiled/smali_classes7'];
      
      // VIP-related keywords for conservative matching
      const vipKeywords = ['vip', 'premium', 'member', 'subscribe', 'paid', 'pro', 'svip', 'isvip', 'ispremium'];
      
      console.log('   🔍 Scanning for VIP-related data models...');
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        this.walkDirectory(smaliDir, (filePath, fileName) => {
          if (!fileName.endsWith('.smali')) return;
          if (!this.isModifiableFile(filePath, false)) return;
          
          try {
            let content = fs.readFileSync(filePath, 'utf8');
            let changed = false;
            const fileNameLower = fileName.toLowerCase();
            
            // CONSERVATIVE: ONLY patch data model classes (no shortcuts)
            const isDataModel = fileNameLower.includes('model') || 
                               fileNameLower.includes('dto') || 
                               fileNameLower.includes('entity') ||
                               fileNameLower.includes('response') ||
                               fileNameLower.includes('bean') ||
                               fileNameLower.includes('user') ||
                               fileNameLower.includes('account');
            
            // STRICT: Must be a data model class - no VipFile shortcut to avoid corrupting service/auth classes
            if (!isDataModel) return;
            
            // Find boolean fields that are VIP-related
            const fieldPattern = /\.field\s+(?:private|public|protected)?\s*(?:static|final)?\s*(\w+):Z/g;
            let fieldMatches = [...content.matchAll(fieldPattern)];
            
            for (const match of fieldMatches) {
              const fieldName = match[1].toLowerCase();
              const isVipField = vipKeywords.some(kw => fieldName.includes(kw));
              
              if (!isVipField) continue;
              
              console.log(`   🎯 Found VIP field: ${match[1]} in ${fileName}`);
              
              // SAFE: Replace entire method body for zero-parameter getter
              // Try field name as-is first (since it might already have is/get prefix)
              const getterPatterns = [
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi'),
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?get${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi'),
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?is${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi')
              ];
              
              for (const pattern of getterPatterns) {
                const originalContent = content;
                content = this.replaceMethodBody(content, pattern, 
                  `    # VIP Bypass - APK Editor\n    const/4 v0, 0x1\n    return v0`);
                
                if (content !== originalContent) {
                  changed = true;
                  console.log(`   ✅ Patched: ${match[1]}() → return true`);
                }
              }
            }
            
            // Find integer VIP level fields
            const intFieldPattern = /\.field\s+(?:private|public|protected)?\s*(?:static|final)?\s*(\w+):I/g;
            let intMatches = [...content.matchAll(intFieldPattern)];
            
            for (const match of intMatches) {
              const fieldName = match[1].toLowerCase();
              if (!['viplevel', 'memberlevel', 'sviplevel'].some(kw => fieldName.includes(kw))) continue;
              
              console.log(`   🎯 Found VIP level field: ${match[1]} in ${fileName}`);
              
              const levelPattern = new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?get${match[1]}\\(\\)I[\\s\\S]*?\\.end method`, 'gi');
              const originalContent = content;
              content = this.replaceMethodBody(content, levelPattern,
                `    # Max VIP Level - APK Editor\n    const/16 v0, 0x270f\n    return v0`);
              
              if (content !== originalContent) {
                changed = true;
                console.log(`   ✅ Patched: get${match[1]}() → return 9999`);
              }
            }

            if (changed) {
              fs.writeFileSync(filePath, content, 'utf8');
              modified++;
            }
          } catch (e) {
            // Skip
          }
        });
      }

      if (modified > 0) {
        console.log(`   ✅ Modified ${modified} files with VIP bypass`);
        this.modifications.applied += modified;
      } else {
        console.log('   ⚠️  No VIP patterns found in data models');
        console.log('   💡 App might use server-side validation');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }
  
  // Helper: Scan VIP strings from resources
  scanVIPStrings() {
    const vipStrings = [];
    const stringsPath = path.join(this.outputDir, 'res', 'values', 'strings.xml');
    
    if (!fs.existsSync(stringsPath)) return vipStrings;
    
    try {
      const content = fs.readFileSync(stringsPath, 'utf8');
      const vipKeywords = ['vip', 'premium', 'subscribe', 'member', 'unlock', 'paid', 'pro'];
      
      const stringMatches = content.matchAll(/<string\s+name="([^"]+)">([^<]+)<\/string>/g);
      for (const match of stringMatches) {
        const key = match[1].toLowerCase();
        const value = match[2].toLowerCase();
        
        if (vipKeywords.some(kw => key.includes(kw) || value.includes(kw))) {
          vipStrings.push({ key: match[1], value: match[2] });
        }
      }
    } catch (e) {
      // Skip
    }
    
    return vipStrings;
  }

  // 3. Unlock All Episodes - SAFE version with full method body replacement
  async unlockAllEpisodes() {
    console.log('\n🎬 [3/8] Unlock All Episodes (Safe Edition)');
    
    try {
      let modified = 0;
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3', 
                         'decompiled/smali_classes4', 'decompiled/smali_classes5', 'decompiled/smali_classes6', 'decompiled/smali_classes7'];
      
      // CONSERVATIVE: Only target specific lock-related fields
      const lockKeywords = ['lock', 'locked', 'islocked', 'islock'];
      const unlockKeywords = ['unlock', 'unlocked', 'free', 'available'];
      
      console.log('   🔍 Scanning for episode/content data models...');
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        this.walkDirectory(smaliDir, (filePath, fileName) => {
          if (!fileName.endsWith('.smali')) return;
          if (!this.isModifiableFile(filePath, false)) return;
          
          try {
            let content = fs.readFileSync(filePath, 'utf8');
            let changed = false;
            const fileNameLower = fileName.toLowerCase();
            
            // CONSERVATIVE: Only patch data model classes
            const isDataModel = fileNameLower.includes('model') || 
                               fileNameLower.includes('dto') || 
                               fileNameLower.includes('entity') ||
                               fileNameLower.includes('response') ||
                               fileNameLower.includes('item') ||
                               fileNameLower.includes('bean') ||
                               fileNameLower.includes('episode') ||
                               fileNameLower.includes('drama') ||
                               fileNameLower.includes('video') ||
                               fileNameLower.includes('album');
            
            if (!isDataModel) return;
            
            // Find boolean lock/unlock fields
            const fieldPattern = /\.field\s+(?:private|public|protected)?\s*(?:static|final)?\s*(\w+):Z/g;
            let fieldMatches = [...content.matchAll(fieldPattern)];
            
            for (const match of fieldMatches) {
              const fieldName = match[1].toLowerCase();
              const isLockField = lockKeywords.some(kw => fieldName.includes(kw));
              const isUnlockField = unlockKeywords.some(kw => fieldName.includes(kw));
              
              if (!isLockField && !isUnlockField) continue;
              
              console.log(`   🎯 Found lock field: ${match[1]} in ${fileName}`);
              
              // SAFE: Replace entire method body for zero-parameter getters
              // Try field name as-is first (since it might already have is/get prefix)
              const getterPatterns = [
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi'),
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?get${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi'),
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?is${match[1]}\\(\\)Z[\\s\\S]*?\\.end method`, 'gi')
              ];
              
              const returnValue = isLockField ? '0x0' : '0x1';  // isLocked→false, isUnlocked→true
              const comment = isLockField ? 'Unlocked' : 'Available';
              
              for (const pattern of getterPatterns) {
                const originalContent = content;
                content = this.replaceMethodBody(content, pattern,
                  `    # ${comment} - APK Editor\n    const/4 v0, ${returnValue}\n    return v0`);
                
                if (content !== originalContent) {
                  changed = true;
                  console.log(`   ✅ Patched: ${match[1]}() → return ${returnValue === '0x0' ? 'false' : 'true'}`);
                }
              }
            }
            
            // Find integer price fields  
            const intFieldPattern = /\.field\s+(?:private|public|protected)?\s*(?:static|final)?\s*(\w+):I/g;
            let intMatches = [...content.matchAll(intFieldPattern)];
            
            for (const match of intMatches) {
              const fieldName = match[1].toLowerCase();
              if (!['price', 'cost', 'coin', 'point', 'diamond', 'episodeprice'].some(kw => fieldName.includes(kw))) continue;
              
              console.log(`   🎯 Found price field: ${match[1]} in ${fileName}`);
              
              // SAFE: Replace entire method body - try field name as-is first
              const pricePatterns = [
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?${match[1]}\\(\\)I[\\s\\S]*?\\.end method`, 'gi'),
                new RegExp(`\\.method\\s+public\\s+(?:final\\s+)?get${match[1]}\\(\\)I[\\s\\S]*?\\.end method`, 'gi')
              ];
              let originalContent = content;
              
              for (const pricePattern of pricePatterns) {
                originalContent = content;
                content = this.replaceMethodBody(content, pricePattern,
                  `    # Free - APK Editor\n    const/4 v0, 0x0\n    return v0`);
                
                if (content !== originalContent) {
                  changed = true;
                  console.log(`   ✅ Made free: ${match[1]}() → return 0`);
                  break; // Found and patched, move to next field
                }
              }
            }

            if (changed) {
              fs.writeFileSync(filePath, content, 'utf8');
              modified++;
            }
          } catch (e) {
            // Skip
          }
        });
      }

      if (modified > 0) {
        console.log(`   ✅ Modified ${modified} files with episode unlock`);
        this.modifications.applied += modified;
      } else {
        console.log('   ⚠️  No lock patterns found in data models');
        console.log('   💡 App might use server-side validation');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 4. Enable Screen Recording/Screenshot
  async enableScreenRecording() {
    console.log('\n🎥 [4/8] Enable Screen Recording');
    
    const manifestPath = path.join(this.outputDir, 'AndroidManifest.xml');
    
    try {
      if (!fs.existsSync(manifestPath)) {
        console.log('   ⚠️  Manifest not found');
        this.modifications.skipped++;
        return;
      }

      let content = fs.readFileSync(manifestPath, 'utf8');
      let added = 0;

      // Also disable FLAG_SECURE if present in activities
      if (content.includes('FLAG_SECURE') || content.includes('android:windowSecure')) {
        content = content.replace(/android:windowSecure="true"/g, 'android:windowSecure="false"');
        added++;
      }

      // Add media projection permission
      if (!content.includes('android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION')) {
        const insertPos = content.indexOf('<application');
        if (insertPos > 0) {
          content = content.slice(0, insertPos) + 
            '<uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION" />\n    ' +
            content.slice(insertPos);
          added++;
        }
      }

      if (added > 0) {
        fs.writeFileSync(manifestPath, content, 'utf8');
        console.log(`   ✅ Modified manifest for screen recording`);
        this.modifications.applied++;
      } else {
        console.log('   ⚠️  Already configured');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 5. Bypass Login - Scan all app package files for login patterns
  async bypassLogin() {
    console.log('\n🚫 [5/8] Bypass Login');
    
    try {
      let modified = 0;
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
      
      // Login-related keywords
      const loginKeywords = ['login', 'auth', 'user', 'account', 'session', 'token'];
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        this.walkDirectory(smaliDir, (filePath, fileName) => {
          if (!fileName.endsWith('.smali')) return;
          if (!this.isModifiableFile(filePath)) return;
          
          try {
            let content = fs.readFileSync(filePath, 'utf8');
            let changed = false;
            const fileNameLower = fileName.toLowerCase();
            
            // Check if file is login-related
            const isLoginFile = loginKeywords.some(kw => fileNameLower.includes(kw));
            
            // Pattern 1: Methods that check if logged in (should return true)
            const loggedInPattern = /\.method\s+(?:public|private|protected)?\s*(?:static|final)?\s*\w*(?:is|has|check)(?:LoggedIn|Logged|Login|Auth|Authenticated)\w*\([^)]*\)Z[\s\S]*?\.end method/gi;
            
            content = content.replace(loggedInPattern, (match) => {
              // Force return true: const/4 vX, 0x0 -> const/4 vX, 0x1
              let newMatch = match.replace(
                /const\/4\s+(v\d+|p\d+),\s+0x0(\s*\n\s*(?:\n\s*)?return(?:-object)?\s+\1)/g,
                'const/4 $1, 0x1$2'
              );
              if (newMatch !== match) {
                changed = true;
                console.log(`   📝 Bypassed login in ${fileName}`);
              }
              return newMatch;
            });
            
            // Pattern 2: Methods that check if need login (should return false)
            const needLoginPattern = /\.method\s+(?:public|private)?\s*\w*(?:need|require|should)(?:Login|Auth)\w*\([^)]*\)Z[\s\S]*?\.end method/gi;
            
            content = content.replace(needLoginPattern, (match) => {
              // Force return false: const/4 vX, 0x1 -> const/4 vX, 0x0
              let newMatch = match.replace(
                /const\/4\s+(v\d+|p\d+),\s+0x1(\s*\n\s*(?:\n\s*)?return(?:-object)?\s+\1)/g,
                'const/4 $1, 0x0$2'
              );
              if (newMatch !== match) {
                changed = true;
                console.log(`   📝 Bypassed need-login in ${fileName}`);
              }
              return newMatch;
            });
            
            // Pattern 3: For login-related files, inject bypass at session check methods
            if (isLoginFile) {
              const sessionPattern = /\.method\s+(?:public|private)?\s*\w*(?:get|is)(?:Valid|Active)(?:Session|Token)\w*\(\)Z([\s\S]*?)\.end method/gi;
              
              content = content.replace(sessionPattern, (match, body) => {
                if (body.includes('.locals')) {
                  const localsMatch = match.match(/\.locals\s+(\d+)/);
                  if (localsMatch && parseInt(localsMatch[1]) > 0) {
                    let newMatch = match.replace(
                      /(\.locals\s+\d+)/,
                      '$1\n\n    const/4 v0, 0x1\n    return v0'
                    );
                    if (newMatch !== match) {
                      changed = true;
                      console.log(`   📝 Force-validated session in ${fileName}`);
                    }
                    return newMatch;
                  }
                }
                return match;
              });
            }

            if (changed) {
              fs.writeFileSync(filePath, content, 'utf8');
              modified++;
            }
          } catch (e) {
            // Skip
          }
        });
      }

      if (modified > 0) {
        console.log(`   ✅ Modified ${modified} files`);
        this.modifications.applied += modified;
      } else {
        console.log('   ⚠️  No login patterns found');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 6. Disable Cleanup/Integrity Detection
  async disableCleanupDetection() {
    console.log('\n🧹 [6/8] Disable Cleanup Detection');
    
    try {
      let modified = 0;
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        this.walkDirectory(smaliDir, (filePath, fileName) => {
          if (!fileName.endsWith('.smali')) return;
          if (!this.isModifiableFile(filePath)) return;
          
          try {
            let content = fs.readFileSync(filePath, 'utf8');
            let changed = false;
            
            // Pattern 1: Root/integrity detection methods (should return false - not detected)
            const rootCheckPattern = /\.method\s+(?:public|private|protected)?\s*(?:static|final)?\s*\w*(?:is|check|detect|has)(?:Rooted|Root|Modified|Tampered|Integrity|Debugger|Emulator)\w*\([^)]*\)Z[\s\S]*?\.end method/gi;
            
            content = content.replace(rootCheckPattern, (match) => {
              // Force return false (not detected): const/4 vX, 0x1 -> const/4 vX, 0x0
              let newMatch = match.replace(
                /const\/4\s+(v\d+|p\d+),\s+0x1(\s*\n\s*(?:\n\s*)?return(?:-object)?\s+\1)/g,
                'const/4 $1, 0x0$2'
              );
              if (newMatch !== match) {
                changed = true;
                console.log(`   📝 Disabled root check in ${fileName}`);
              }
              return newMatch;
            });
            
            // Pattern 2: Signature verification methods (force return true - verified)
            const signaturePattern = /\.method\s+(?:public|private)?\s*\w*(?:verify|check)(?:Signature|Certificate|App)\w*\([^)]*\)Z[\s\S]*?\.end method/gi;
            
            content = content.replace(signaturePattern, (match) => {
              // Force return true (verified): const/4 vX, 0x0 -> const/4 vX, 0x1
              let newMatch = match.replace(
                /const\/4\s+(v\d+|p\d+),\s+0x0(\s*\n\s*(?:\n\s*)?return(?:-object)?\s+\1)/g,
                'const/4 $1, 0x1$2'
              );
              if (newMatch !== match) {
                changed = true;
                console.log(`   📝 Bypassed signature check in ${fileName}`);
              }
              return newMatch;
            });

            if (changed) {
              fs.writeFileSync(filePath, content, 'utf8');
              modified++;
            }
          } catch (e) {
            // Skip
          }
        });
      }

      if (modified > 0) {
        console.log(`   ✅ Modified ${modified} files`);
        this.modifications.applied += modified;
      } else {
        console.log('   ⚠️  No cleanup detection found');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 7. Disable Unnecessary Permissions
  async disableUnnecessaryPermissions() {
    console.log('\n🔐 [7/8] Disable Unnecessary Permissions');
    
    const manifestPath = path.join(this.outputDir, 'AndroidManifest.xml');
    
    try {
      if (!fs.existsSync(manifestPath)) {
        console.log('   ⚠️  Manifest not found');
        this.modifications.skipped++;
        return;
      }

      let content = fs.readFileSync(manifestPath, 'utf8');
      let removed = 0;

      // Permissions yang tidak diperlukan untuk fungsi utama app
      const unnecessaryPerms = [
        'com.google.android.gms.permission.AD_ID',
        'android.permission.ACCESS_ADSERVICES_ATTRIBUTION',
        'android.permission.ACCESS_ADSERVICES_AD_ID',
        'android.permission.ACCESS_ADSERVICES_TOPICS'
      ];

      for (const perm of unnecessaryPerms) {
        const regex = new RegExp(`\\s*<uses-permission android:name="${perm.replace(/\./g, '\\.')}"[^>]*/>`, 'g');
        if (content.match(regex)) {
          content = content.replace(regex, '');
          removed++;
        }
      }

      if (removed > 0) {
        fs.writeFileSync(manifestPath, content, 'utf8');
        console.log(`   ✅ Removed ${removed} ad-related permissions`);
        this.modifications.applied += removed;
      } else {
        console.log('   ⚠️  No unnecessary permissions found');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 8. Bypass VPN Block
  async bypassVPNBlock() {
    console.log('\n🌐 [8/8] Bypass VPN Block');
    
    try {
      let modified = 0;
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
      
      // VPN-related keywords
      const vpnKeywords = ['vpn', 'proxy', 'network', 'connection'];
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        this.walkDirectory(smaliDir, (filePath, fileName) => {
          if (!fileName.endsWith('.smali')) return;
          if (!this.isModifiableFile(filePath)) return;
          
          try {
            let content = fs.readFileSync(filePath, 'utf8');
            let changed = false;
            const fileNameLower = fileName.toLowerCase();
            
            // Check if file is VPN-related
            const isVpnFile = vpnKeywords.some(kw => fileNameLower.includes(kw));
            
            // Pattern 1: VPN detection methods (should return false - no VPN detected)
            const vpnDetectPattern = /\.method\s+(?:public|private|protected)?\s*(?:static|final)?\s*\w*(?:is|has|check|detect|using)(?:Vpn|VPN|Proxy|Connected)\w*\([^)]*\)Z[\s\S]*?\.end method/gi;
            
            content = content.replace(vpnDetectPattern, (match) => {
              // Force return false: const/4 vX, 0x1 -> const/4 vX, 0x0
              let newMatch = match.replace(
                /const\/4\s+(v\d+|p\d+),\s+0x1(\s*\n\s*(?:\n\s*)?return(?:-object)?\s+\1)/g,
                'const/4 $1, 0x0$2'
              );
              if (newMatch !== match) {
                changed = true;
                console.log(`   📝 Bypassed VPN check in ${fileName}`);
              }
              return newMatch;
            });
            
            // Pattern 2: For VPN-related files, force bypass on network state methods
            if (isVpnFile) {
              const networkPattern = /\.method\s+(?:public|private)?\s*\w*(?:is|check)(?:Blocked|Restricted|Limited)\w*\(\)Z([\s\S]*?)\.end method/gi;
              
              content = content.replace(networkPattern, (match, body) => {
                if (body.includes('.locals')) {
                  const localsMatch = match.match(/\.locals\s+(\d+)/);
                  if (localsMatch && parseInt(localsMatch[1]) > 0) {
                    let newMatch = match.replace(
                      /(\.locals\s+\d+)/,
                      '$1\n\n    const/4 v0, 0x0\n    return v0'
                    );
                    if (newMatch !== match) {
                      changed = true;
                      console.log(`   📝 Force-bypassed network block in ${fileName}`);
                    }
                    return newMatch;
                  }
                }
                return match;
              });
            }

            if (changed) {
              fs.writeFileSync(filePath, content, 'utf8');
              modified++;
            }
          } catch (e) {
            // Skip
          }
        });
      }

      if (modified > 0) {
        console.log(`   ✅ Modified ${modified} files`);
        this.modifications.applied += modified;
      } else {
        console.log('   ⚠️  No VPN block found');
        this.modifications.skipped++;
      }
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // 9. Rename Package Name to avoid Play Store redirect (DYNAMIC)
  async renamePackage(newPackageName = null) {
    console.log('\n📦 [9/9] Rename Package Name');
    
    const manifestPath = path.join(this.outputDir, 'AndroidManifest.xml');
    
    try {
      if (!fs.existsSync(manifestPath)) {
        console.log('   ⚠️  Manifest not found');
        this.modifications.skipped++;
        return;
      }

      let content = fs.readFileSync(manifestPath, 'utf8');
      
      // Get original package name
      const pkgMatch = content.match(/package="([^"]+)"/);
      if (!pkgMatch) {
        console.log('   ⚠️  Package name not found');
        this.modifications.skipped++;
        return;
      }
      
      const oldPackageName = pkgMatch[1];
      
      // DYNAMIC: Generate new package name based on original
      if (!newPackageName) {
        const timestamp = Date.now().toString().slice(-6);
        newPackageName = `${oldPackageName}.mod${timestamp}`;
      }
      
      console.log(`   📝 Old: ${oldPackageName}`);
      console.log(`   📝 New: ${newPackageName}`);
      
      // Replace package name in manifest
      content = content.replace(
        `package="${oldPackageName}"`,
        `package="${newPackageName}"`
      );
      
      // Replace in all package references
      content = content.replace(
        new RegExp(oldPackageName.replace(/\./g, '\\.'), 'g'),
        newPackageName
      );
      
      fs.writeFileSync(manifestPath, content, 'utf8');
      
      // Rename smali directories
      const oldPath = oldPackageName.replace(/\./g, '/');
      const newPath = newPackageName.replace(/\./g, '/');
      
      const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
      
      for (const smaliDir of smaliDirs) {
        if (!fs.existsSync(smaliDir)) continue;
        
        const oldSmaliPath = path.join(smaliDir, oldPath);
        const newSmaliPath = path.join(smaliDir, newPath);
        
        if (fs.existsSync(oldSmaliPath)) {
          // Create new directory structure
          const newParentDir = path.dirname(newSmaliPath);
          if (!fs.existsSync(newParentDir)) {
            execSync(`mkdir -p "${newParentDir}"`);
          }
          
          // Move directory
          execSync(`mv "${oldSmaliPath}" "${newSmaliPath}"`);
          console.log(`   ✅ Renamed smali path in ${path.basename(smaliDir)}`);
        }
      }
      
      // Update package references in all smali files
      this.updatePackageReferencesInSmali(oldPackageName, newPackageName);
      
      console.log('   ✅ Package renamed successfully');
      this.modifications.applied++;
    } catch (error) {
      console.log(`   ❌ Failed: ${error.message}`);
      this.modifications.failed++;
    }
  }

  // Update package references in smali files
  updatePackageReferencesInSmali(oldPackage, newPackage) {
    const oldPath = oldPackage.replace(/\./g, '/');
    const newPath = newPackage.replace(/\./g, '/');
    
    const smaliDirs = ['decompiled/smali', 'decompiled/smali_classes2', 'decompiled/smali_classes3'];
    
    for (const smaliDir of smaliDirs) {
      if (!fs.existsSync(smaliDir)) continue;
      
      this.walkDirectory(smaliDir, (filePath, fileName) => {
        if (!fileName.endsWith('.smali')) return;
        
        try {
          let content = fs.readFileSync(filePath, 'utf8');
          const originalContent = content;
          
          // Replace Lcom/old/package/ with Lcom/new/package/
          content = content.replace(
            new RegExp(`L${oldPath.replace(/\//g, '\\/')}/`, 'g'),
            `L${newPath}/`
          );
          
          // Replace .class references
          content = content.replace(
            new RegExp(oldPackage.replace(/\./g, '\\.'), 'g'),
            newPackage
          );
          
          if (content !== originalContent) {
            fs.writeFileSync(filePath, content, 'utf8');
          }
        } catch (e) {
          // Skip
        }
      });
    }
  }

  // Apply all modifications
  async applyAllModifications(features) {
    console.log('\n🎯 APPLYING MODIFICATIONS');
    console.log('=' .repeat(50));
    console.log(`Target: ${this.analysis.packageName || 'Unknown'}`);
    console.log('Mode: SAFE (only app package, exclude libraries)');
    console.log('=' .repeat(50));

    if (features.fixScreenOff !== false) await this.fixScreenOff();
    if (features.bypassVIP !== false) await this.bypassVIP();
    if (features.unlockEpisodes !== false) await this.unlockAllEpisodes();
    if (features.screenRecording !== false) await this.enableScreenRecording();
    if (features.bypassLogin !== false) await this.bypassLogin();
    if (features.disableCleanup !== false) await this.disableCleanupDetection();
    if (features.disablePermissions !== false) await this.disableUnnecessaryPermissions();
    if (features.bypassVPN !== false) await this.bypassVPNBlock();
    
    // IMPORTANT: Rename package to avoid Play Store redirect (DYNAMIC)
    if (features.renamePackage !== false) {
      // Pass null to use auto-generated name based on original package
      await this.renamePackage();
    }

    this.printSummary();
  }

  printSummary() {
    console.log('\n' + '='.repeat(50));
    console.log('📊 MODIFICATION SUMMARY');
    console.log('='.repeat(50));
    console.log(`✅ Applied: ${this.modifications.applied}`);
    console.log(`⚠️  Skipped: ${this.modifications.skipped}`);
    console.log(`❌ Failed: ${this.modifications.failed}`);
    console.log('='.repeat(50));
  }
}

// ============================================================================
// CLASS: APKEditorWorkflow
// ============================================================================
class APKEditorWorkflow {
  constructor() {
    this.selectedAPK = null;
    this.analysis = null;
  }

  // Cleanup before starting
  cleanup() {
    const dirsToClean = [
      'decompiled',
      'modified.apk',
      'final-signed.apk',
      'jadx-1.4.7.zip',
      'merged-base.apk'
    ];

    for (const dir of dirsToClean) {
      try {
        if (fs.existsSync(dir)) {
          if (fs.statSync(dir).isDirectory()) {
            execSync(`rm -rf "${dir}" 2>/dev/null`, { stdio: 'ignore' });
          } else {
            fs.unlinkSync(dir);
          }
        }
      } catch (e) {
        // Silent fail
      }
    }
  }

  async handleSplitAPKs() {
    const apkDir = 'apk';
    if (!fs.existsSync(apkDir)) {
      console.log('   ⚠️  APK directory not found');
      return;
    }

    const files = fs.readdirSync(apkDir);
    
    // Check for .apks files and extract them first
    const apksFiles = files.filter(f => f.toLowerCase().endsWith('.apks'));
    
    if (apksFiles.length > 0) {
      console.log(`\n📦 Detected .apks files (App Bundle archives):`);
      for (const apksFile of apksFiles) {
        console.log(`   📄 ${apksFile}`);
        try {
          const apksPath = path.join(apkDir, apksFile);
          const baseName = path.basename(apksFile, '.apks');
          const extractDir = path.join(apkDir, `${baseName}_extracted`);
          
          console.log(`   🔓 Extracting ${apksFile}...`);
          
          // Create extraction directory
          if (!fs.existsSync(extractDir)) {
            fs.mkdirSync(extractDir);
          }
          
          // Extract .apks (it's just a ZIP file)
          execSync(`unzip -q -o "${apksPath}" -d "${extractDir}"`, { stdio: 'inherit' });
          
          // Move all APK files to main apk directory
          const extractedFiles = fs.readdirSync(extractDir);
          const extractedApks = extractedFiles.filter(f => f.endsWith('.apk'));
          
          for (const apk of extractedApks) {
            const srcPath = path.join(extractDir, apk);
            const destPath = path.join(apkDir, apk);
            
            // Don't overwrite if already exists
            if (!fs.existsSync(destPath)) {
              execSync(`mv "${srcPath}" "${destPath}"`);
            }
          }
          
          // Cleanup extraction directory
          execSync(`rm -rf "${extractDir}"`);
          
          console.log(`   ✅ Extracted ${extractedApks.length} APK files from ${apksFile}`);
          console.log(`   📝 Original .apks file kept at: ${apksPath}\n`);
        } catch (e) {
          console.log(`   ❌ Failed to extract ${apksFile}: ${e.message}`);
        }
      }
    }
    
    // Re-scan after extraction
    const updatedFiles = fs.readdirSync(apkDir);
    const baseAPK = updatedFiles.find(f => f === 'base.apk');
    const splitAPKs = updatedFiles.filter(f => f.startsWith('split_config.') && f.endsWith('.apk'));

    if (baseAPK && splitAPKs.length > 0) {
      console.log(`\n📦 Detected split APKs:`);
      console.log(`   Base: ${baseAPK}`);
      console.log(`   Splits: ${splitAPKs.length} files`);
      console.log(`\n⚠️  IMPORTANT: You have split APKs (App Bundle format)`);
      console.log(`   Split APKs result in smaller modified size.`);
      console.log(`   Recommendation: Use universal APK instead.`);
      console.log(`\n💡 To get universal APK:`);
      console.log(`   1. Download from APKPure/APKMirror (select "APK" not "XAPK")`);
      console.log(`   2. Or use bundletool to merge splits`);
      console.log(`\n   Continuing with base.apk only...\n`);
    } else if (!baseAPK && splitAPKs.length === 0) {
      console.log('   ✅ Single APK detected (recommended)\n');
    }
  }

  async run() {
    console.log('\n' + '='.repeat(70));
    console.log('🚀 APK EDITOR - ANALYZER & MODIFIER');
    console.log('='.repeat(70));

    // Cleanup old files
    console.log('\n🧹 Cleaning up old files...');
    this.cleanup();
    console.log('✅ Cleanup complete\n');

    // Step 1: Setup tools
    console.log('[1/6] Setting up tools...');
    const toolsReady = await ToolBuilder.setupTools();
    if (!toolsReady) {
      console.error('❌ Failed to setup tools');
      process.exit(1);
    }

    // Step 2: Detect and merge split APKs if needed
    console.log('[2/6] Checking for split APKs...');
    await this.handleSplitAPKs();

    // Step 3: Select APK
    console.log('[3/6] Selecting APK...');
    const selector = new APKSelector();
    this.selectedAPK = await selector.selectAPKInteractive();
    
    if (!this.selectedAPK) {
      console.error('❌ No APK selected');
      process.exit(1);
    }

    // Step 4: Analyze APK
    console.log('\n[4/6] Analyzing APK structure...');
    const analyzer = new APKAnalyzer(this.selectedAPK.path);
    this.analysis = await analyzer.analyze();
    
    if (!this.analysis) {
      console.error('❌ Analysis failed');
      process.exit(1);
    }

    analyzer.printSummary();
    analyzer.saveReport(`analysis-${Date.now()}.json`);

    // Step 5: Ask for modifications
    console.log('\n[5/6] Preparing modifications...');
    const features = this.getModificationFeatures();
    
    // Step 6: Apply modifications
    console.log('\n[6/6] Applying modifications...');
    const modifier = new APKModifier(this.selectedAPK.path, this.analysis);
    await modifier.applyAllModifications(features);

    // Recompile and sign
    console.log('\n[7/7] Recompiling and signing...');
    const success = await this.recompileAndSign();

    if (success) {
      console.log('\n' + '='.repeat(70));
      console.log('🎉 SUCCESS!');
      console.log('='.repeat(70));
      console.log('📱 Output: final-signed.apk');
      console.log('📍 Ready to install on your device');
      console.log('='.repeat(70) + '\n');
    } else {
      console.error('\n❌ Build failed - decompiled folder preserved for debugging');
      process.exit(1);
    }

    // Cleanup large files
    console.log('\n🧹 Cleaning up temporary files...');
    try {
      execSync('rm -rf decompiled modified.apk 2>/dev/null', { stdio: 'ignore' });
      console.log('✅ Cleanup complete');
    } catch (e) {
      // Silently fail
    }
  }

  getModificationFeatures() {
    return {
      fixScreenOff: true,       // SAFE: add permission only
      bypassVIP: true,          // SAFE: uses full method body replacement (no dead code)
      unlockEpisodes: true,     // SAFE: uses full method body replacement (no dead code)
      screenRecording: true,    // SAFE: add permission only
      bypassLogin: false,       // RISKY: still uses old pattern - DISABLED
      disableCleanup: false,    // RISKY: still uses old pattern - DISABLED
      disablePermissions: true, // SAFE: remove permission only
      bypassVPN: false,         // RISKY: still uses old pattern - DISABLED
      renamePackage: false      // Keep original package name
    };
  }

  async recompileAndSign() {
    try {
      console.log('   🔨 Recompiling APK...');
      console.log('   (This may take several minutes for large APKs...)');
      
      // Try with aapt2 first (recommended)
      try {
        const compileCmd = 'java -Xmx1536m -jar apktool.jar b decompiled -o modified.apk --use-aapt2';
        execSync(compileCmd, { 
          timeout: 900000, // 15 minutes
          maxBuffer: 150 * 1024 * 1024, // 150MB buffer
          stdio: 'inherit'
        });
      } catch (e) {
        console.log('   ⚠️  aapt2 failed, trying with aapt...');
        
        // Fallback to aapt
        const fallbackCmd = 'java -Xmx1536m -jar apktool.jar b decompiled -o modified.apk';
        execSync(fallbackCmd, { 
          timeout: 900000,
          maxBuffer: 150 * 1024 * 1024,
          stdio: 'inherit'
        });
      }
      
      if (!fs.existsSync('modified.apk')) {
        console.error('   ❌ Recompile failed - no APK generated');
        console.error('   💡 Check decompiled/ folder for errors');
        return false;
      }
      
      const modSize = fs.statSync('modified.apk').size;
      console.log(`   ✅ Recompiled successfully (${(modSize / 1024 / 1024).toFixed(2)} MB)`);

      console.log('   🔐 Signing APK...');
      this.signAPK();
      console.log('   ✅ Signed successfully');

      return true;
    } catch (error) {
      console.error('   ❌ Recompile/Sign failed:', error.message);
      console.error('   💡 Decompiled folder preserved for debugging');
      return false;
    }
  }

  signAPK() {
    const modifiedApk = 'modified.apk';
    const keystore = 'my-key.keystore';

    try {
      // Generate keystore if not exists
      if (!fs.existsSync(keystore)) {
        execSync(
          'keytool -genkey -v -keystore ' + keystore + ' -alias mykey ' +
          '-keyalg RSA -keysize 2048 -validity 10000 ' +
          '-storepass password -keypass password ' +
          '-dname "CN=APKEditor, OU=Android, O=Replit, L=Cloud, S=Cloud, C=ID"',
          { stdio: 'ignore' }
        );
      }

      // Sign APK
      execSync(
        `jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 ` +
        `-keystore ${keystore} -storepass password -keypass password ` +
        `${modifiedApk} mykey`,
        { stdio: 'ignore' }
      );

      // Copy to final
      execSync(`cp ${modifiedApk} final-signed.apk`);
    } catch (error) {
      throw new Error('Signing failed: ' + error.message);
    }
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================
if (require.main === module) {
  const workflow = new APKEditorWorkflow();
  workflow.run().catch(error => {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = APKEditorWorkflow;
