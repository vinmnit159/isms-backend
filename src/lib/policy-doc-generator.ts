/**
 * Generates a structured, editable .docx policy document from a template definition.
 *
 * The document contains the following sections:
 *   1. Cover page  (title, version, status, date, ISO references)
 *   2. Purpose
 *   3. Scope
 *   4. Policy Statement  (sub-sections derived from the template)
 *   5. Roles & Responsibilities
 *   6. Compliance & Enforcement
 *   7. Related Documents
 *   8. Review & Revision History
 *
 * Placeholders like [Organization Name] are intentionally left for the user to fill in.
 */

import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  AlignmentType,
  BorderStyle,
  Table,
  TableRow,
  TableCell,
  WidthType,
  ShadingType,
  PageBreak,
  convertInchesToTwip,
  Header,
  Footer,
  PageNumberElement,
} from 'docx';

// ── colour palette ───────────────────────────────────────────────────────────
const BRAND_BLUE   = '1E3A5F';  // dark navy  — headings
const ACCENT_BLUE  = '2563EB';  // vivid blue — ISO pill bg
const LIGHT_GREY   = 'F3F4F6';  // table header fill
const MID_GREY     = '6B7280';  // body text helper colour
const WHITE        = 'FFFFFF';

// ── helpers ──────────────────────────────────────────────────────────────────

function heading1(text: string): Paragraph {
  return new Paragraph({
    text,
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 400, after: 120 },
    run: { color: BRAND_BLUE, bold: true },
  });
}

function heading2(text: string): Paragraph {
  return new Paragraph({
    text,
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 80 },
    run: { color: BRAND_BLUE },
  });
}

function body(text: string, options: { bold?: boolean; italic?: boolean; color?: string } = {}): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({
        text,
        bold: options.bold,
        italics: options.italic,
        color: options.color ?? '111827',
        size: 22, // 11 pt
      }),
    ],
    spacing: { after: 120 },
  });
}

function placeholder(label: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `[${label}]`, bold: true, color: ACCENT_BLUE, size: 22 }),
    ],
    spacing: { after: 120 },
  });
}

function bullet(text: string): Paragraph {
  return new Paragraph({
    children: [new TextRun({ text, size: 22, color: '111827' })],
    bullet: { level: 0 },
    spacing: { after: 80 },
  });
}

function hrParagraph(): Paragraph {
  return new Paragraph({
    border: {
      bottom: { color: 'D1D5DB', space: 1, style: BorderStyle.SINGLE, size: 6 },
    },
    spacing: { after: 200 },
  });
}

function isoRefTable(refs: string[]): Table {
  const cellStyle = {
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
  };

  const headerRow = new TableRow({
    children: [
      new TableCell({
        ...cellStyle,
        shading: { type: ShadingType.SOLID, color: BRAND_BLUE, fill: BRAND_BLUE },
        children: [
          new Paragraph({
            children: [new TextRun({ text: 'ISO 27001:2022 Annex A Reference', bold: true, color: WHITE, size: 20 })],
          }),
        ],
        width: { size: 3500, type: WidthType.DXA },
      }),
      new TableCell({
        ...cellStyle,
        shading: { type: ShadingType.SOLID, color: BRAND_BLUE, fill: BRAND_BLUE },
        children: [
          new Paragraph({
            children: [new TextRun({ text: 'Control Title', bold: true, color: WHITE, size: 20 })],
          }),
        ],
        width: { size: 6000, type: WidthType.DXA },
      }),
    ],
  });

  const dataRows = refs.map(ref =>
    new TableRow({
      children: [
        new TableCell({
          ...cellStyle,
          shading: { type: ShadingType.SOLID, color: LIGHT_GREY, fill: LIGHT_GREY },
          children: [
            new Paragraph({
              children: [new TextRun({ text: ref, bold: true, color: ACCENT_BLUE, size: 20 })],
            }),
          ],
        }),
        new TableCell({
          ...cellStyle,
          children: [
            new Paragraph({
              children: [new TextRun({ text: '[Control title — see ISO 27001:2022 Annex A]', color: MID_GREY, size: 20 })],
            }),
          ],
        }),
      ],
    })
  );

  return new Table({
    rows: [headerRow, ...dataRows],
    width: { size: 100, type: WidthType.PERCENTAGE },
  });
}

function revisionTable(): Table {
  const cellStyle = { margins: { top: 60, bottom: 60, left: 100, right: 100 } };

  const headerRow = new TableRow({
    children: ['Version', 'Date', 'Author', 'Description of Changes'].map(h =>
      new TableCell({
        ...cellStyle,
        shading: { type: ShadingType.SOLID, color: LIGHT_GREY, fill: LIGHT_GREY },
        children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 20 })] })],
      })
    ),
  });

  const dataRow = new TableRow({
    children: ['1.0', '[Date]', '[Author]', 'Initial version'].map(val =>
      new TableCell({
        ...cellStyle,
        children: [new Paragraph({ children: [new TextRun({ text: val, size: 20, color: '374151' })] })],
      })
    ),
  });

  return new Table({
    rows: [headerRow, dataRow],
    width: { size: 100, type: WidthType.PERCENTAGE },
  });
}

// ── Policy-specific body content ─────────────────────────────────────────────

interface PolicySection {
  heading: string;
  paragraphs: string[];
  bullets?: string[];
}

function getSections(name: string, description: string): PolicySection[] {
  // Generic sections that apply to every policy, enriched with the template description.
  const common: PolicySection[] = [
    {
      heading: '3. Policy Statement',
      paragraphs: [
        `[Organization Name] is committed to maintaining the highest standards of information security. This section sets out the specific requirements for the ${name}.`,
        description,
      ],
      bullets: [
        'All personnel must comply with this policy and any supporting procedures or guidelines.',
        'Exceptions must be formally approved and documented by the Information Security Manager.',
        'This policy is reviewed at least annually or following a significant incident or change.',
      ],
    },
    {
      heading: '3.1 Requirements',
      paragraphs: [
        'The following requirements apply to all personnel, systems, and processes in scope:',
      ],
      bullets: [
        '[Requirement 1 — describe the first specific control or rule]',
        '[Requirement 2 — describe the second specific control or rule]',
        '[Requirement 3 — describe the third specific control or rule]',
        '[Add additional requirements as needed]',
      ],
    },
    {
      heading: '3.2 Prohibited Activities',
      paragraphs: ['The following activities are explicitly prohibited:'],
      bullets: [
        '[Prohibited activity 1]',
        '[Prohibited activity 2]',
        '[Add additional prohibited activities as needed]',
      ],
    },
  ];

  return common;
}

// ── Main export ───────────────────────────────────────────────────────────────

export interface PolicyTemplateInput {
  name: string;
  version: string;
  status: string;
  category: string;
  isoReferences: string[];
  description: string;
}

/**
 * Generate an in-memory .docx Buffer for the given policy template.
 */
export async function generatePolicyDocument(template: PolicyTemplateInput): Promise<Buffer> {
  const today = new Date().toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });

  const sections = getSections(template.name, template.description);

  const doc = new Document({
    creator: 'ISMS Platform',
    title: template.name,
    description: template.description,
    styles: {
      paragraphStyles: [
        {
          id: 'Heading1',
          name: 'Heading 1',
          run: { bold: true, color: BRAND_BLUE, size: 28 },
          paragraph: { spacing: { before: 400, after: 120 } },
        },
        {
          id: 'Heading2',
          name: 'Heading 2',
          run: { bold: true, color: BRAND_BLUE, size: 24 },
          paragraph: { spacing: { before: 280, after: 80 } },
        },
      ],
    },
    sections: [
      {
        properties: {
          page: {
            margin: {
              top: convertInchesToTwip(1),
              right: convertInchesToTwip(1),
              bottom: convertInchesToTwip(1),
              left: convertInchesToTwip(1.2),
            },
          },
        },
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                children: [
                  new TextRun({ text: '[Organization Name]  |  ', color: MID_GREY, size: 18 }),
                  new TextRun({ text: template.name, bold: true, color: BRAND_BLUE, size: 18 }),
                  new TextRun({ text: `  |  v${template.version}`, color: MID_GREY, size: 18 }),
                ],
                alignment: AlignmentType.RIGHT,
                border: { bottom: { color: 'D1D5DB', space: 1, style: BorderStyle.SINGLE, size: 4 } },
              }),
            ],
          }),
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                children: [
                  new TextRun({ text: 'CONFIDENTIAL  |  ', color: MID_GREY, size: 18 }),
                  new TextRun({ text: 'Page ', color: MID_GREY, size: 18 }),
                  new PageNumberElement(),
                  new TextRun({ text: '  |  ', color: MID_GREY, size: 18 }),
                  new TextRun({ text: `© ${new Date().getFullYear()} [Organization Name]. All rights reserved.`, color: MID_GREY, size: 18 }),
                ],
                alignment: AlignmentType.CENTER,
                border: { top: { color: 'D1D5DB', space: 1, style: BorderStyle.SINGLE, size: 4 } },
              }),
            ],
          }),
        },
        children: [
          // ── Cover page ──────────────────────────────────────────────────────
          new Paragraph({
            children: [new TextRun({ text: template.category.toUpperCase(), color: MID_GREY, bold: true, size: 20 })],
            alignment: AlignmentType.CENTER,
            spacing: { before: 800, after: 200 },
          }),
          new Paragraph({
            children: [new TextRun({ text: template.name, bold: true, color: BRAND_BLUE, size: 52 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 160 },
          }),
          new Paragraph({
            children: [new TextRun({ text: `Version ${template.version}  |  Status: ${template.status}`, color: MID_GREY, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 120 },
          }),
          new Paragraph({
            children: [new TextRun({ text: `Effective Date: ${today}`, color: MID_GREY, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 120 },
          }),
          new Paragraph({
            children: [new TextRun({ text: 'Organization: ', bold: true, color: MID_GREY, size: 22 }), new TextRun({ text: '[Organization Name]', bold: true, color: ACCENT_BLUE, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 120 },
          }),
          new Paragraph({
            children: [new TextRun({ text: 'Document Owner: ', bold: true, color: MID_GREY, size: 22 }), new TextRun({ text: '[Owner Name / Role]', bold: true, color: ACCENT_BLUE, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 120 },
          }),
          new Paragraph({
            children: [new TextRun({ text: 'Approved By: ', bold: true, color: MID_GREY, size: 22 }), new TextRun({ text: '[Approver Name / Title]', bold: true, color: ACCENT_BLUE, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 400 },
          }),

          hrParagraph(),

          // ISO references table on cover
          new Paragraph({
            children: [new TextRun({ text: 'Applicable ISO 27001:2022 Controls', bold: true, color: BRAND_BLUE, size: 22 })],
            alignment: AlignmentType.CENTER,
            spacing: { after: 160 },
          }),
          isoRefTable(template.isoReferences),

          new Paragraph({ children: [new PageBreak()], spacing: { after: 0 } }),

          // ── 1. Purpose ──────────────────────────────────────────────────────
          heading1('1. Purpose'),
          body(
            `This document defines the ${template.name} for [Organization Name]. The purpose of this policy is to:`
          ),
          bullet(`Establish clear requirements and responsibilities related to ${template.name.toLowerCase()}.`),
          bullet('Ensure compliance with ISO 27001:2022 and applicable laws and regulations.'),
          bullet('Protect [Organization Name]\'s information assets and those of its clients and partners.'),
          bullet('[Add additional purpose statements specific to your organization]'),

          hrParagraph(),

          // ── 2. Scope ────────────────────────────────────────────────────────
          heading1('2. Scope'),
          body('This policy applies to:'),
          bullet('All employees, contractors, consultants, and temporary staff of [Organization Name].'),
          bullet('All information systems, networks, and data owned or managed by [Organization Name].'),
          bullet('All locations where [Organization Name] operations are conducted, including remote work environments.'),
          bullet('[Specify any additional scope inclusions or exclusions relevant to your organization]'),
          body('Out of scope:', { bold: true }),
          bullet('[List any explicit exclusions, e.g. "Third-party-owned systems not connected to [Organization Name] networks"]'),

          hrParagraph(),

          // ── 3. Policy Statement (template-specific) ──────────────────────────
          ...sections.flatMap(section => [
            heading1(section.heading),
            ...section.paragraphs.map(p => body(p)),
            ...(section.bullets ?? []).map(b => bullet(b)),
            hrParagraph(),
          ]),

          // ── 4. Roles & Responsibilities ─────────────────────────────────────
          heading1('4. Roles and Responsibilities'),
          heading2('Information Security Manager / CISO'),
          bullet(`Own and maintain this ${template.name}.`),
          bullet('Communicate policy requirements to relevant stakeholders.'),
          bullet('Review and update this policy at least annually.'),
          heading2('IT / Security Team'),
          bullet('Implement the technical controls defined in this policy.'),
          bullet('Monitor compliance and report exceptions.'),
          heading2('System / Asset Owners'),
          bullet('Ensure systems and assets under their ownership comply with this policy.'),
          bullet('Promptly report non-compliance or incidents to the Information Security team.'),
          heading2('All Personnel'),
          bullet('Read, understand, and comply with this policy.'),
          bullet('Report suspected violations to [security@organizationname.com].'),
          bullet('[Define additional roles and responsibilities as needed]'),

          hrParagraph(),

          // ── 5. Compliance & Enforcement ─────────────────────────────────────
          heading1('5. Compliance and Enforcement'),
          body(
            'Compliance with this policy is mandatory for all persons within scope. Violations may result in disciplinary action up to and including termination of employment or contract, and where applicable, civil or criminal legal proceedings.'
          ),
          body(
            '[Organization Name] will monitor compliance through [describe monitoring approach — e.g. periodic audits, automated tooling, management reviews].'
          ),

          hrParagraph(),

          // ── 6. Exceptions ────────────────────────────────────────────────────
          heading1('6. Exceptions'),
          body(
            'Requests for exceptions to this policy must be submitted in writing to the Information Security Manager for review and approval. All approved exceptions must be documented, time-bound, and subject to compensating controls.'
          ),

          hrParagraph(),

          // ── 7. Related Documents ─────────────────────────────────────────────
          heading1('7. Related Documents'),
          bullet('Information Security Policy'),
          bullet('Risk Assessment and Risk Treatment Process'),
          bullet('Statement of Applicability'),
          bullet('[List additional related policies, procedures, or standards]'),

          hrParagraph(),

          // ── 8. Definitions ────────────────────────────────────────────────────
          heading1('8. Definitions'),
          body('[Term 1]:', { bold: true }),
          body('[Definition of Term 1]'),
          body('[Term 2]:', { bold: true }),
          body('[Definition of Term 2]'),
          body('[Add additional terms as needed]'),

          hrParagraph(),

          // ── 9. Revision History ──────────────────────────────────────────────
          heading1('9. Revision History'),
          revisionTable(),
        ],
      },
    ],
  });

  return Packer.toBuffer(doc);
}
