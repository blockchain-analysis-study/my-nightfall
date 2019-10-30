/**
@module
@author iAmMichaelConnor
@desc Run from within nightfall/zkp/code
*/

import { argv } from 'yargs';
import util from 'util';
import os from 'os';
import fs from 'fs';
import path from 'path';
import inquirer from 'inquirer';
// eslint-disable-next-line import/extensions
import { compile, setup, exportVerifier } from '@eyblockchain/zokrates.js';
import keyExtractor from './keyExtractor';

const readdirAsync = util.promisify(fs.readdir);

const isDirectory = source => fs.lstatSync(source).isDirectory();
const getDirectories = source =>
  fs
    .readdirSync(source)
    .map(name => path.join(source, name))
    .filter(isDirectory);

/**
 * Returns an array of all imported files in dataLines.
 * @param {String[]} dataLines - Array of lines that make up a .code file.
 * @returns {String[]} - Array of imported files in dataLines.
 */
function getImportFiles(dataLines) {
  const cpDataLines = [...dataLines];
  return cpDataLines.reduce((accArr, line) => {
    // parses each line of the .code file for a line of the form:
    // import "./aux-adder.code" as ADD
    //  and extracts "./aux-adder.code"
    // ZoKrates' own packages will be ignored, as they are of the form:
    // import "LIBSNARK/sha256compression"
    //  which doesn't include ".code", and so are ignored.
    line.replace(/((import ")+(.+\.+code+)+("+))+?/g, (m1, m2, ii, c) => {
      if (c !== undefined) {
        accArr.push(c);
      }
    });
    return accArr;
  }, []);
}

/**
 * Ensures that any imported dependencies in code files are present.
 * @param {String} codeFileDirectory - Directory in which code file resides (i.e., /gm17/ft-burn)
 * @param {String} codeFile - Name of code file (i.e., ft-burn)
 * @throws {Error} - If a dependent code file is not found
 */
async function checkForImportFiles(codeFileDirectory, codeFile) {
  const dataLines = fs
    .readFileSync(`${codeFileDirectory}/${codeFile}`)
    .toString('UTF8')
    .split(os.EOL);

  // Assumes that any dependencies will exist in the /code/gm17 directory.
  const codeFileParentPath = path.join(codeFileDirectory, '../../');

  let importFiles = [];
  importFiles = getImportFiles(dataLines);
  if (!(importFiles === undefined || importFiles.length === 0)) {
    // array is nonempty
    for (let j = 0; j < importFiles.length; j += 1) {
      const file = importFiles[j];
      if (!fs.existsSync(codeFileParentPath + file)) {
        // throw new Error(`Imported file in ${codeFile}: ${file} not found in ${codeFileParentPath}`);
      }
    }
  }
}

/**
 * Copies files over to /code/safe-dump, and then checks to ensure imports are present.
 * @param {string} codeDirectory - Directory that contains the .code file (e.g., '/code/gm17/ft-burn')
 */
async function filingChecks(codeDirectory) {
  const files = await readdirAsync(codeDirectory);

  // Looking for the .code file, e.g., ft-burn.out
  let codeFileName;
  let codeFileExt;
  for (let j = 0; j < files.length; j += 1) {
    codeFileName = files[j].substring(0, files[j].lastIndexOf('.'));
    codeFileExt = files[j].substring(files[j].lastIndexOf('.') + 1, files[j].length);

    // Output directory
    // Looking for a .code file, but not out.code
    if (codeFileExt === 'code' && codeFileName !== 'out') {
      break;
    }
  }

  // Copies files over to /code/safe-dump
  const safeDumpDirectory = path.join(codeDirectory, '../../safe-dump');
  fs.copyFileSync(
    `${codeDirectory}/${codeFileName}.${codeFileExt}`,
    `${safeDumpDirectory}/${codeFileName}.${codeFileExt}`,
    err => {
      if (err) throw new Error('Error while copying file:', err);
    },
  );

  await checkForImportFiles(`${codeDirectory}`, `${codeFileName}.${codeFileExt}`);
}

/**
 * Given a directory that contains a .code file, calls Zokrates compile, setup and export verifier
 * @param {String} directoryPath
 */
async function generateZokratesFiles(directoryPath) {
  const files = await readdirAsync(directoryPath);

  const directoryWithSlash = directoryPath.endsWith('/') ? directoryPath : `${directoryPath}/`;

  let codeFile;
  // Look for a .code file that's not out.code. That's the file we're compiling.
  for (let j = 0; j < files.length; j += 1) {
    if (files[j].endsWith('.code') && files[j] !== 'out.code') {
      codeFile = files[j];
      break;
    }
  }

  console.log('Compiling at', `${directoryWithSlash}${codeFile}`);

  // Generate out.code and out in the same directory.
  await compile(`${directoryWithSlash}${codeFile}`, directoryWithSlash);
  console.log('Finished compiling at', directoryPath);

  // Generate verification.key and proving.key
  await setup(
    `${directoryWithSlash}out`,
    directoryWithSlash,
    'gm17',
    'verification.key',
    'proving.key',
  );
  console.log('Finished setup at', directoryPath);

  await exportVerifier(
    `${directoryWithSlash}/verification.key`,
    directoryWithSlash,
    'verifier.sol',
    'gm17',
  );
  console.log('Finished export-verifier at', directoryPath);

  const vkJson = await keyExtractor(`${directoryWithSlash}verifier.sol`, true);

  // Create a JSON with the file name but without .code
  fs.writeFileSync(`${directoryWithSlash}${codeFile.split('.')[0]}-vk.json`, vkJson, err => {
    if (err) {
      console.error(err);
    }
  });
  console.log(directoryPath, 'is done setting up.');
}

/**
 * Calls Zokrates' compile, setup, and export-verifier on a single directory that contains a .code file.
 * @param {String} codeDirectory - A specific directory that contains a .code file (e.g., /code/gm17/ft-burn)
 */
async function runSetup(codeDirectory) {
  await filingChecks(codeDirectory);

  await generateZokratesFiles(codeDirectory);
}

/**
 * Calls zokrates' compile, setup, and export-verifier on all directories in `/zkp/code/gm17`.
 * @param {String} codeDirectory - Directory in which all the .code subfolders live.
 */
async function runSetupAll(codeDirectory) {
  // Array of all directories in the above directory.
  const codeDirectories = getDirectories(codeDirectory);

  await Promise.all(
    codeDirectories.map(subdirectory => {
      return filingChecks(subdirectory);
    }),
  );

  // The files don't compile correctly when we Promise.all these, so we're doing sequentially.
  // Maybe too much processing.
  for (let j = 0; j < codeDirectories.length; j += 1) {
    // eslint-disable-next-line no-await-in-loop
    await generateZokratesFiles(codeDirectories[j]);
  }
}

/**
 * Trusted setup for Nightfall. Either compiles all directories in /code/gm17, or a single directory using the -i flag.
 */
async function main() {
  // arguments to the command line:
  // i - filename
  const { i } = argv; // file name - pass the directory of the .code file as the '-i' parameter

  // a - arguments for compute-witness
  const a0 = argv.a; // arguments for compute-witness (within quotes "")
  let a1 = [];
  if (!(a0 === undefined || a0 === '')) {
    a1 = a0.split(' ');
  } else {
    a1 = null;
  }

  if (!i) {
    console.log(
      "The '-i' option has not been specified.\nThat's OK, we can go ahead and loop through every .code file.\nHOWEVER, if you wanted to choose just one file, cancel this process, and instead use option -i (see the README-trusted-setup)",
    );
    console.log('Be warned, this could take up to an hour!');

    const carryOn = await inquirer.prompt([
      {
        type: 'yesno',
        name: 'continue',
        message: 'Continue?',
        choices: ['y', 'n'],
      },
    ]);
    if (carryOn.continue !== 'y') return;

    try {
      await runSetupAll(`${process.cwd()}/code/gm17`); // we'll do all .code files if no option is specified
    } catch (err) {
      throw new Error(`Trusted setup failed: ${err}`);
    }
  } else {
    await runSetup(a1);
  }
}

// RUN
main().catch(err => console.log(err));
